package org.cysecurity.cspf.jvl.config;

public class AppConfig {
    
    /**
     * Loads API key from environment variables.
     * Falls back to default value if not found (for testing only).
     * 
     * @return The Stripe API key
     * @throws IllegalStateException if key is not configured in production
     */
    public static String getStripeApiKey() {
        String key = System.getenv("STRIPE_API_KEY");
        if (key == null || key.isEmpty()) {
            throw new IllegalStateException(
                "STRIPE_API_KEY environment variable not set. " +
                "Please configure it in .env or system environment."
            );
        }
        return key;
    }

    /**
     * Loads database URL from environment variables.
     */
    public static String getDatabaseUrl() {
        String url = System.getenv("DB_URL");
        if (url == null || url.isEmpty()) {
            throw new IllegalStateException("DB_URL environment variable not set");
        }
        return url;
    }

    /**
     * Loads database user from environment variables.
     */
    public static String getDatabaseUser() {
        String user = System.getenv("DB_USER");
        if (user == null || user.isEmpty()) {
            throw new IllegalStateException("DB_USER environment variable not set");
        }
        return user;
    }

    /**
     * Loads database password from environment variables.
     */
    public static String getDatabasePassword() {
        String password = System.getenv("DB_PASSWORD");
        if (password == null || password.isEmpty()) {
            throw new IllegalStateException("DB_PASSWORD environment variable not set");
        }
        return password;
    }

    /**
     * Loads AWS Access Key ID from environment variables.
     */
    public static String getAwsAccessKeyId() {
        String key = System.getenv("AWS_ACCESS_KEY_ID");
        if (key == null || key.isEmpty()) {
            throw new IllegalStateException("AWS_ACCESS_KEY_ID environment variable not set");
        }
        return key;
    }

    /**
     * Loads AWS Secret Access Key from environment variables.
     */
    public static String getAwsSecretAccessKey() {
        String key = System.getenv("AWS_SECRET_ACCESS_KEY");
        if (key == null || key.isEmpty()) {
            throw new IllegalStateException("AWS_SECRET_ACCESS_KEY environment variable not set");
        }
        return key;
    }

    /**
     * Loads webhook secret from environment variables.
     */
    public static String getWebhookSecret() {
        String secret = System.getenv("WEBHOOK_SECRET");
        if (secret == null || secret.isEmpty()) {
            throw new IllegalStateException("WEBHOOK_SECRET environment variable not set");
        }
        return secret;
    }
}
