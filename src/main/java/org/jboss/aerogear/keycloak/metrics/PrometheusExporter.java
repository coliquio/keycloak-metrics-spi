package org.jboss.aerogear.keycloak.metrics;

import io.prometheus.client.CollectorRegistry;
import io.prometheus.client.Counter;
import io.prometheus.client.Gauge;
import io.prometheus.client.Histogram;
import io.prometheus.client.exporter.common.TextFormat;
import io.prometheus.client.hotspot.DefaultExports;
import org.jboss.logging.Logger;
import org.keycloak.events.Event;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.models.*;

import java.io.*;
import java.util.List;
import java.util.Map;

public final class PrometheusExporter {

    private final static String PROVIDER_KEYCLOAK_OPENID = "keycloak";
    private final static PrometheusExporter INSTANCE = new PrometheusExporter();
    private final static Logger logger = Logger.getLogger(PrometheusExporter.class);

    // these fields are package private on purpose
    final Counter totalLogins;
    final Counter totalFailedLoginAttempts;
    final Counter totalRegistrations;
    final Counter responseErrors;
    final Counter eventCounter;
    final Counter adminEventCounter;
    final Histogram requestDuration;
    final Gauge activeSessions;


    private PrometheusExporter() {
        // The metrics collector needs to be a singleton because requiring a
        // provider from the KeyCloak session (session#getProvider) will always
        // create a new instance. Not sure if this is a bug in the SPI implementation
        // or intentional but better to avoid this. The metrics object is single-instance
        // anyway and all the Gauges are suggested to be static (it does not really make
        // sense to record the same metric in multiple places)

        // package private on purpose
        totalLogins = Counter.build()
            .name("keycloak_logins")
            .help("Total successful logins")
            .labelNames("realm", "provider")
            .register();

        // package private on purpose
        totalFailedLoginAttempts = Counter.build()
            .name("keycloak_failed_login_attempts")
            .help("Total failed login attempts")
            .labelNames("realm", "provider", "error", "client_id")
            .register();

        // package private on purpose
        totalRegistrations = Counter.build()
            .name("keycloak_registrations")
            .help("Total registered users")
            .labelNames("realm", "provider")
            .register();

        responseErrors = Counter.build()
            .name("keycloak_response_errors")
            .help("Total number of error responses")
            .labelNames("code", "method", "route")
            .register();

        requestDuration = Histogram.build()
            .name("keycloak_request_duration")
            .help("Request duration")
            .buckets(2, 10, 100, 1000)
            .labelNames("method", "route")
            .register();

        eventCounter = Counter.build()
            .name("keycloak_user_event")
            .labelNames("realm", "event_name")
            .help("Keycloak event")
            .register();

        adminEventCounter = Counter.build()
            .name("keycloak_admin_event")
            .labelNames("realm", "event_name", "resource")
            .help("Keycloak admin event")
            .register();

        // Active sessions count
        activeSessions = Gauge.build()
            .name("keycloak_active_sessions_count")
            .help("Active user sessions count")
            .labelNames("realm", "client_id")
            .register();

        // Initialize the default metrics for the hotspot VM
        DefaultExports.initialize();
    }

    public static PrometheusExporter instance() {
        return INSTANCE;
    }

    /**
     * Count generic user event
     *
     * @param event User event
     */
    public void recordGenericEvent(final Event event) {
        eventCounter
            .labels(event.getRealmId(), event.getType().name())
            .inc();
    }

    /**
     * Count generic admin event
     *
     * @param event Admin event
     */
    public void recordGenericAdminEvent(final AdminEvent event) {
        adminEventCounter
            .labels(event.getRealmId(), event.getOperationType().name(), event.getResourceType().name())
            .inc();
    }

    /**
     * Increase the number of currently logged in users
     *
     * @param event Login event
     */
    public void recordLogin(final Event event) {
        final String provider = getIdentityProvider(event);

        totalLogins.labels(event.getRealmId(), provider).inc();
    }

    /**
     * Increase the number registered users
     *
     * @param event Register event
     */
    public void recordRegistration(final Event event) {
        final String provider = getIdentityProvider(event);

        totalRegistrations.labels(event.getRealmId(), provider).inc();
    }


    /**
     * Increase the number of failed login attempts
     *
     * @param event LoginError event
     */
    public void recordLoginError(final Event event) {
        final String provider = getIdentityProvider(event);

        totalFailedLoginAttempts.labels(event.getRealmId(), provider, event.getError(), event.getClientId()).inc();
    }

    /**
     * Record the duration between one request and response
     *
     * @param amt    The duration in milliseconds
     * @param method HTTP method of the request
     * @param route  Request route / path
     */
    public void recordRequestDuration(double amt, String method, String route) {
        requestDuration.labels(method, route).observe(amt);
    }

    /**
     * Increase the response error count by a given method and route
     *
     * @param code   The returned http status code
     * @param method The request method used
     * @param route  The request route / path
     */
    public void recordResponseError(int code, String method, String route) {
        responseErrors.labels(Integer.toString(code), method, route).inc();
    }

    /**
     * Retrieve the identity prodiver name from event details or
     * default to {@value #PROVIDER_KEYCLOAK_OPENID}.
     *
     * @param event User event
     * @return Identity provider name
     */
    private String getIdentityProvider(Event event) {
        String identityProvider = null;
        if (event.getDetails() != null) {
            identityProvider = event.getDetails().get("identity_provider");
        }
        if (identityProvider == null) {
            identityProvider = PROVIDER_KEYCLOAK_OPENID;
        }
        return identityProvider;
    }

    /**
     * Write the Prometheus formatted values of all counters and
     * gauges to the stream
     *
     * @param stream Output stream
     * @throws IOException
     */
    public void export(final OutputStream stream) throws IOException {
        final Writer writer = new BufferedWriter(new OutputStreamWriter(stream));
        TextFormat.write004(writer, CollectorRegistry.defaultRegistry.metricFamilySamples());
        writer.flush();
    }

    public void export(final OutputStream stream, KeycloakSession session) throws IOException {
        RealmProvider realmProvider = session.getProvider(RealmProvider.class);
        UserSessionProvider userSessionProvider = session.getProvider(UserSessionProvider.class);

        for (RealmModel realm : realmProvider.getRealms()) {
            Map<String, Long> stats = userSessionProvider.getActiveClientSessionStats(realm, false);

            try {
                List<ClientModel> clients = realm.getClients();
                for (ClientModel client : clients) {
                    activeSessions
                        .labels(realm.getName(), client.getClientId())
                        .set(stats.getOrDefault(client.getId(), (long) 0));
                }


            } catch (Exception e) {
                logger.error(e.getStackTrace());
            }
        }

        final Writer writer = new BufferedWriter(new OutputStreamWriter(stream));
        TextFormat.write004(writer, CollectorRegistry.defaultRegistry.metricFamilySamples());
        writer.flush();
    }
}
