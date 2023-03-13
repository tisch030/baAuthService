package eu.firmax.cms.auth.local.log;

public enum AuthenticationOperation {

    /**
     * Indicates a failed authentication attempt, f.e. a wrong password.
     */
    AUTHENTICATION_FAILED,

    /**
     * Indicates a server side error during the authentication.
     */
    AUTHENTICATION_ERROR,

    /**
     * Indicates a successful login.
     */
    LOGIN,

    /**
     * Indicates a successful logout.
     */
    LOGOUT
}
