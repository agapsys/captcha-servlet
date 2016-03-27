/*
 * Copyright 2015 Agapsys Tecnologia Ltda-ME.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.agapsys.captcha;

import com.github.cage.Cage;
import com.github.cage.GCage;
import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

public class CaptchaServlet extends HttpServlet {

	// CLASS SCOPE =============================================================
	private static final Cage CAGE = new GCage();
	private static final String ATR_SESSION_TOKEN = "com.agapsys.captcha.token";
	private static final Object INIT_MUTEX = new Object();
	
	private static CaptchaServlet instance = null;
	
	public static CaptchaServlet getInstance() {
		synchronized(INIT_MUTEX) {
			if (instance == null)
				throw new IllegalStateException("Servlet was not initialized yet");
			
			return instance;
		}
	}
	// =========================================================================

	// INSTANCE SCOPE ==========================================================
	/**
	 * Tests given token against stored one.
	 * @param req request used to retrieve stored cookie
	 * @param token token to be tested
	 * @return a boolean indicating if given token is valid.
	 */
	public final boolean isValid(HttpServletRequest req, String token) {
		String storedToken = getStoredToken(req);
		
		if (storedToken == null)
			return false;
		
		return storedToken.equals(token);
	}
	
	/**
	 * Associates a token with an user.
	 * Default implementation stores the token into user session.
	 * @param req HTTP request
	 * @param resp HTTP response
	 * @param token token to be associated with an user.
	 */
	protected void store(HttpServletRequest req, HttpServletResponse resp, String token) {
		HttpSession session = req.getSession();
		session.setAttribute(ATR_SESSION_TOKEN, token);
	}
	
	/**
	 * Returns the token previously associated with given request.
	 * Default implementation retrieves the token from user session.
	 * @param req HTTP request
	 * @return associated token
	 */
	protected String getStoredToken(HttpServletRequest req) {
		HttpSession session = req.getSession(false);
		
		if (session == null)
			return null;
		
		return (String) session.getAttribute(ATR_SESSION_TOKEN);
	}
	
	protected Cage getCage() {
		return CAGE;
	}
	
	@Override
	protected final void service(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		synchronized (INIT_MUTEX) {
			if (instance == null)
				instance = this;
		}
		
		if (!req.getMethod().equals("GET")) {
			resp.sendError(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
		} else {
			String token = getCage().getTokenGenerator().next();
			store(req, resp, token);

			resp.setContentType("image/" + getCage().getFormat());
			resp.setHeader("Cache-Control", "no-cache, no-store");
			resp.setHeader("Pragma", "no-cache");
			long time = System.currentTimeMillis();
			resp.setDateHeader("Last-Modified", time);
			resp.setDateHeader("Date", time);
			resp.setDateHeader("Expires", time);
		
		    CAGE.draw(token, resp.getOutputStream());
		}
	}
	// =========================================================================
}
