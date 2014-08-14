package com.sourceallies.demo;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.HashMap;
import java.util.Map;

public class BasicAuthDemoServlet extends HttpServlet {
    Map<String, String> securePasswordDatabase = new HashMap<String, String>();

    public void init(ServletConfig config) throws ServletException {
        super.init(config);
        securePasswordDatabase.put("sai", "sai");
    }

    public void doGet(HttpServletRequest req, HttpServletResponse res)
            throws ServletException, IOException {
        res.setContentType("text/html");
        PrintWriter out = res.getWriter();
        String auth = req.getHeader("Authorization");
        if (!authorized(auth)) {
            res.setHeader("WWW-Authenticate", "BASIC realm=\"basic-auth-demo\"");
            res.sendError(401);
        } else {
            out.println("You did it");
        }
    }

    private boolean authorized(String auth) throws IOException {
        if (auth == null) {
            return false;
        }

        if (!auth.toUpperCase().startsWith("BASIC ")) {
            return false;
        }

        Credentials credentials = getCredentials(auth);

        return credentials != null &&
                securePasswordDatabase.get(credentials.username).equals(credentials.password);
    }

    private Credentials getCredentials(String auth) throws IOException {
        String userpassEncoded = auth.substring(6);
        sun.misc.BASE64Decoder dec = new sun.misc.BASE64Decoder();
        String userPass = new String(dec.decodeBuffer(userpassEncoded));


        Credentials credentials = new Credentials();
        String[] authFields = userPass.split(":");

        if (authFields.length != 2) {
            return null;
        }

        credentials.username = authFields[0];
        credentials.password = authFields[1];
        return credentials;
    }

    private class Credentials {
        public String username;
        public String password;
    }
}
