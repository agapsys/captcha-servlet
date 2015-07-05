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

public final class CaptchaServlet extends HttpServlet {

	// CLASS SCOPE =============================================================
	private static final Cage CAGE = new GCage();
	private static final String ATR_SESSION_TOKEN = "com.agapsys.captcha.token";

	/**
	 * Generates a token an stores in session
	 * @param request request
	 */
	private static void generateToken(HttpServletRequest request) {
		HttpSession session = request.getSession();
		
		String token = CAGE.getTokenGenerator().next();
		session.setAttribute(ATR_SESSION_TOKEN, token);
	}

	/**
	 * @return Token stored in session
	 * @param request request
	 */
	private static String getToken(HttpServletRequest request) {
		HttpSession session = request.getSession();
		String token = (String) session.getAttribute(ATR_SESSION_TOKEN);
		return token;
	}
	
	/**
	 * Check if given token is valid
	 * @param request request
	 * @param token token to be tested
	 * @return check result
	 */
	public static boolean checkToken(HttpServletRequest request, String token) throws IllegalArgumentException {
		if (token == null || token.isEmpty())
			throw new IllegalArgumentException("Null/Empty token");
		
		return token.equals(getToken(request));
	}
		
	// =========================================================================

	// INSTANCE SCOPE ==========================================================
	@Override
	protected void service(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		if (!req.getMethod().equals("GET")) {
			resp.sendError(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
		} else {
			String token = getToken(req);

			resp.setContentType("image/" + CAGE.getFormat());
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
