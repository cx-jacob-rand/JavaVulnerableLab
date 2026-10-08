import java.sql.Connection;
import java.sql.DriverManager;
import java.util.Properties;
import org.cysecurity.cspf.jvl.config.AppConfig;

public class PaymentServiceClient {

    // SECURITY: All secrets are now loaded from environment variables via AppConfig
    // See .env.example for configuration template
    // Never hardcode secrets in source code

    public Connection getDatabaseConnection() throws Exception {
        Properties props = new Properties();
        props.setProperty("user", AppConfig.getDatabaseUser());
        props.setProperty("password", AppConfig.getDatabasePassword());
        props.setProperty("ssl", "true");
        return DriverManager.getConnection(AppConfig.getDatabaseUrl(), props);
    }

    public String getStripeKey() {
        return AppConfig.getStripeApiKey();
    }

    public String getAwsAccessKeyId() {
        return AppConfig.getAwsAccessKeyId();
    }

    public String getAwsSecretAccessKey() {
        return AppConfig.getAwsSecretAccessKey();
    }

    public String getWebhookSecret() {
        return AppConfig.getWebhookSecret();
    }
}