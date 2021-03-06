package org.jboss.aerogear.keycloak.metrics;

import org.hamcrest.MatcherAssert;
import org.junit.Before;
import org.junit.Test;
import org.keycloak.events.Event;
import org.keycloak.events.EventType;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.events.admin.OperationType;
import org.keycloak.events.admin.ResourceType;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;

import static org.hamcrest.CoreMatchers.containsString;

@SuppressWarnings("unchecked")
public class PrometheusExporterTest {

    private static final String DEFAULT_REALM = "myrealm";

    @Before
    public void before() {
        PrometheusExporter.instance().totalLogins.clear();
        PrometheusExporter.instance().totalFailedLoginAttempts.clear();
        PrometheusExporter.instance().totalRegistrations.clear();
    }

    @Test
    public void shouldCorrectlyCountLoginWhenIdentityProviderIsDefined() throws IOException {
        final Event login1 = createEvent(EventType.LOGIN, tuple("identity_provider", "THE_ID_PROVIDER"));
        PrometheusExporter.instance().recordLogin(login1);
        assertMetric("keycloak_logins_total", 1, tuple("provider", "THE_ID_PROVIDER"));

        final Event login2 = createEvent(EventType.LOGIN, tuple("identity_provider", "THE_ID_PROVIDER"));
        PrometheusExporter.instance().recordLogin(login2);
        assertMetric("keycloak_logins_total", 2, tuple("provider", "THE_ID_PROVIDER"));
    }

    @Test
    public void shouldCorrectlyCountLoginWhenIdentityProviderIsNotDefined() throws IOException {
        final Event login1 = createEvent(EventType.LOGIN);
        PrometheusExporter.instance().recordLogin(login1);
        assertMetric("keycloak_logins_total", 1, tuple("provider", "keycloak"));

        final Event login2 = createEvent(EventType.LOGIN);
        PrometheusExporter.instance().recordLogin(login2);
        assertMetric("keycloak_logins_total", 2, tuple("provider", "keycloak"));
    }

    @Test
    public void shouldCorrectlyCountLoginsFromDifferentProviders() throws IOException {
        // with id provider defined
        final Event login1 = createEvent(EventType.LOGIN, tuple("identity_provider", "THE_ID_PROVIDER"));
        PrometheusExporter.instance().recordLogin(login1);
        assertMetric("keycloak_logins_total", 1, tuple("provider", "THE_ID_PROVIDER"));

        // without id provider defined
        final Event login2 = createEvent(EventType.LOGIN);
        PrometheusExporter.instance().recordLogin(login2);
        assertMetric("keycloak_logins_total", 1, tuple("provider", "keycloak"));
        assertMetric("keycloak_logins_total", 1, tuple("provider", "THE_ID_PROVIDER"));
    }

    @Test
    public void shouldRecordLoginsPerRealm() throws IOException {
        // realm 1
        final Event login1 = createEvent(EventType.LOGIN, DEFAULT_REALM, tuple("identity_provider", "THE_ID_PROVIDER"));
        PrometheusExporter.instance().recordLogin(login1);

        // realm 2
        final Event login2 = createEvent(EventType.LOGIN, "OTHER_REALM", tuple("identity_provider", "THE_ID_PROVIDER"));
        PrometheusExporter.instance().recordLogin(login2);

        assertMetric("keycloak_logins_total", 1, DEFAULT_REALM, tuple("provider", "THE_ID_PROVIDER"));
        assertMetric("keycloak_logins_total", 1, "OTHER_REALM", tuple("provider", "THE_ID_PROVIDER"));
    }

    @Test
    public void shouldCorrectlyCountLoginError() throws IOException {
        // with id provider defined
        final Event event1 = createEvent(EventType.LOGIN_ERROR, DEFAULT_REALM, "user_not_found", "THE_CLIENT_ID", tuple("identity_provider", "THE_ID_PROVIDER"));
        PrometheusExporter.instance().recordLoginError(event1);
        assertMetric("keycloak_failed_login_attempts_total", 1, tuple("provider", "THE_ID_PROVIDER"), tuple("error", "user_not_found"), tuple("client_id", "THE_CLIENT_ID"));

        // without id provider defined
        final Event event2 = createEvent(EventType.LOGIN_ERROR, DEFAULT_REALM, "user_not_found", "THE_CLIENT_ID");
        PrometheusExporter.instance().recordLoginError(event2);
        assertMetric("keycloak_failed_login_attempts_total", 1, tuple("provider", "keycloak"), tuple("error", "user_not_found"), tuple("client_id", "THE_CLIENT_ID"));
        assertMetric("keycloak_failed_login_attempts_total", 1, tuple("provider", "THE_ID_PROVIDER"), tuple("error", "user_not_found"), tuple("client_id", "THE_CLIENT_ID"));
    }

    @Test
    public void shouldCorrectlyCountRegister() throws IOException {
        // with id provider defined
        final Event event1 = createEvent(EventType.REGISTER, tuple("identity_provider", "THE_ID_PROVIDER"));
        PrometheusExporter.instance().recordRegistration(event1);
        assertMetric("keycloak_registrations_total", 1, tuple("provider", "THE_ID_PROVIDER"));

        // without id provider defined
        final Event event2 = createEvent(EventType.REGISTER);
        PrometheusExporter.instance().recordRegistration(event2);
        assertMetric("keycloak_registrations_total", 1, tuple("provider", "keycloak"));
        assertMetric("keycloak_registrations_total", 1, tuple("provider", "THE_ID_PROVIDER"));
    }

    @Test
    public void shouldCorrectlyRecordGenericEvents() throws IOException {
        final Event event1 = createEvent(EventType.UPDATE_EMAIL);
        PrometheusExporter.instance().recordGenericEvent(event1);
        assertMetric("keycloak_user_events_total", 1, tuple("event_name", "UPDATE_EMAIL"));
        PrometheusExporter.instance().recordGenericEvent(event1);
        assertMetric("keycloak_user_events_total", 2, tuple("event_name", "UPDATE_EMAIL"));


        final Event event2 = createEvent(EventType.REVOKE_GRANT);
        PrometheusExporter.instance().recordGenericEvent(event2);
        assertMetric("keycloak_user_events_total", 1, tuple("event_name", "REVOKE_GRANT"));
        assertMetric("keycloak_user_events_total", 2, tuple("event_name", "UPDATE_EMAIL"));
    }

    @Test
    public void shouldCorrectlyRecordGenericAdminEvents() throws IOException {
        final AdminEvent event1 = new AdminEvent();
        event1.setOperationType(OperationType.ACTION);
        event1.setResourceType(ResourceType.AUTHORIZATION_SCOPE);
        event1.setRealmId(DEFAULT_REALM);
        PrometheusExporter.instance().recordGenericAdminEvent(event1);
        assertMetric("keycloak_admin_events_total", 1, tuple("event_name", "ACTION"), tuple("resource", "AUTHORIZATION_SCOPE"));
        PrometheusExporter.instance().recordGenericAdminEvent(event1);
        assertMetric("keycloak_admin_events_total", 2, tuple("event_name", "ACTION"), tuple("resource", "AUTHORIZATION_SCOPE"));


        final AdminEvent event2 = new AdminEvent();
        event2.setOperationType(OperationType.UPDATE);
        event2.setResourceType(ResourceType.CLIENT);
        event2.setRealmId(DEFAULT_REALM);
        PrometheusExporter.instance().recordGenericAdminEvent(event2);
        assertMetric("keycloak_admin_events_total", 1, tuple("event_name", "UPDATE"), tuple("resource", "CLIENT"));
        assertMetric("keycloak_admin_events_total", 2, tuple("event_name", "ACTION"), tuple("resource", "AUTHORIZATION_SCOPE"));
    }

    @Test
    public void shouldCorrectlyRecordResponseDurations() throws IOException {
        PrometheusExporter.instance().recordRequestDuration(5, "GET", "/");
        assertGenericMetric("keycloak_request_duration_count", 1, tuple("method", "GET"), tuple("route", "/"));
        assertGenericMetric("keycloak_request_duration_sum", 5, tuple("method", "GET"), tuple("route", "/"));
    }

    @Test
    public void shouldCorrectlyRecordResponseErrors() throws IOException {
        PrometheusExporter.instance().recordResponseError(500, "POST", "/");
        assertGenericMetric("keycloak_response_errors_total", 1, tuple("code", "500"), tuple("method", "POST"), tuple("route", "/"));
    }

    private void assertGenericMetric(String metricName, double metricValue, Tuple<String, String>... labels) throws IOException {
        try (ByteArrayOutputStream stream = new ByteArrayOutputStream()) {
            PrometheusExporter.instance().export(stream);
            String result = new String(stream.toByteArray());

            final StringBuilder builder = new StringBuilder();
            builder.append(metricName).append("{");

            for (Tuple<String, String> label : labels) {
                builder.append(label.left).append("=\"").append(label.right).append("\",");
            }

            builder.append("} ").append(metricValue);

            MatcherAssert.assertThat(result, containsString(builder.toString()));
        }
    }

    private void assertMetric(String metricName, double metricValue, String realm, Tuple<String, String>... labels) throws IOException {
        try (ByteArrayOutputStream stream = new ByteArrayOutputStream()) {
            PrometheusExporter.instance().export(stream);
            String result = new String(stream.toByteArray());

            final StringBuilder builder = new StringBuilder();

            builder.append(metricName).append("{");
            builder.append("realm").append("=\"").append(realm).append("\",");

            for (Tuple<String, String> label : labels) {
                builder.append(label.left).append("=\"").append(label.right).append("\",");
            }

            builder.append("} ").append(metricValue);

            MatcherAssert.assertThat(result, containsString(builder.toString()));
        }
    }

    private void assertMetric(String metricName, double metricValue, Tuple<String, String>... labels) throws IOException {
        this.assertMetric(metricName, metricValue, DEFAULT_REALM, labels);
    }

    private Event createEvent(EventType type, String realm, String error, String clientId, Tuple<String, String>... tuples) {
        final Event event = new Event();
        event.setType(type);
        event.setRealmId(realm);
        event.setClientId(clientId);
        if (tuples != null) {
            event.setDetails(new HashMap<>());
            for (Tuple<String, String> tuple : tuples) {
                event.getDetails().put(tuple.left, tuple.right);
            }
        } else {
            event.setDetails(Collections.emptyMap());
        }

        if (error != null) {
            event.setError(error);
        }
        return event;
    }

    private Event createEvent(EventType type, String realm, String error, Tuple<String, String>... tuples) {
        return this.createEvent(type, realm, error, (String) null, tuples);
    }

    private Event createEvent(EventType type, String realm, Tuple<String, String>... tuples) {
        return this.createEvent(type, realm, (String) null, (String) null, tuples);
    }

    private Event createEvent(EventType type, Tuple<String, String>... tuples) {
        return this.createEvent(type, DEFAULT_REALM, (String) null, (String) null, tuples);
    }

    private Event createEvent(EventType type) {
        return createEvent(type, DEFAULT_REALM, (String) null);
    }

    private static <L, R> Tuple<L, R> tuple(L left, R right) {
        return new Tuple<>(left, right);
    }

    private static final class Tuple<L, R> {
        final L left;
        final R right;

        private Tuple(L left, R right) {
            this.left = left;
            this.right = right;
        }
    }
}
