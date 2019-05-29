[![License](https://img.shields.io/:license-Apache2-blue.svg)](http://www.apache.org/licenses/LICENSE-2.0)

# KeyCloak Metrics SPI

A [Service Provider](http://www.keycloak.org/docs/3.0/server_development/topics/providers.html) that adds a metrics endpoint to KeyCloak. The endpoint returns metrics data ready to be scraped by [Prometheus](https://prometheus.io/).

Two distinct providers are defined:

* MetricsEventListener to record the internal KeyCloak events
* MetricsEndpoint to expose the data through a custom endpoint

The endpoint lives under `<url>/auth/realms/<realm>/metrics`. It will return data for all realms, no matter which realm
you use in the URL (you can just default to `/auth/realms/master/metrics`).

## License 

 See [LICENSE file](./LICENSE)

## Running the tests

```sh
$ ./gradlew test
```

## Build

The project is packaged as a jar file and bundles the prometheus client libraries.

```sh
$ ./gradlew jar
```

builds the jar and writes it to _build/libs_.

### Configurable versions for some packages

You can build the project using a different version of Keycloak or Prometheus, running the command:

```sh
$ ./gradlew -PkeycloakVersion="4.7.0.Final" -PprometheusVersion="0.3.0" jar
```

or by changing the `gradle.properties` file in the root of the project.

## Usage

Just drop the jar into the _providers_ subdirectory of your KeyCloak installation.

To enable the event listener via the GUI interface, go to _Manage -> Events -> Config_. The _Event Listeners_ configuration should have an entry named `metrics-listener`.

To enable the event listener via the KeyCloak CLI, such as when building a Docker container, use these commands. (These commands assume /opt/jboss is the KeyCloak home directory, which is used on the _jboss/keycloak_ reference container on Docker Hub.)

    /opt/jboss/keycloak/bin/kcadm.sh config credentials --server http://localhost:8080/auth --realm master --user $KEYCLOAK_USER --password $KEYCLOAK_PASSWORD
    /opt/jboss/keycloak/bin/kcadm.sh update events/config -s "eventsEnabled=true" -s "adminEventsEnabled=true" -s "eventsListeners+=metrics-listener"
    /usr/bin/rm -f /opt/jboss/.keycloak/kcadm.config

## Metrics

For each metric, the endpoint returns 2 or more lines of information:

* **# HELP**: A small description provided by the SPI.
* **# TYPE**: The type of metric, namely _counter_ and _gauge_. More info about types at [prometheus.io/docs](https://prometheus.io/docs/concepts/metric_types/).
* Provided there were any values, the last one recorded. If no value has been recorded yet, no more lines will be given.
* In case the same metric have different labels, there is a different line for each one. By default all metrics are labeled by realm. More info about labels at [prometheus.io/docs](https://prometheus.io/docs/practices/naming/).

Example:
```c
# HELP jvm_memory_bytes_committed Committed (bytes) of a given JVM memory area.
# TYPE jvm_memory_bytes_committed gauge
jvm_memory_bytes_committed{area="heap",} 2.00802304E8
jvm_memory_bytes_committed{area="nonheap",} 2.0217856E8
```

### JVM performance
A variety of JVM metrics are provided

### Generic events
Every single internal Keycloak event is being shared through the endpoint with the metric `keycloak_user_events_total` and `keycloak_admin_events_total`. Most of these events are not likely useful for the majority users but are provided for good measure. Each metric is labelled by the `event_name`, complete list of event names can be found here:

- [User Events](https://www.keycloak.org/docs-api/5.0/javadocs/org/keycloak/events/EventType.html)
- [Admin Events](https://www.keycloak.org/docs-api/5.0/javadocs/org/keycloak/events/admin/OperationType.html)

### Featured events
There are however a few events that are particularly more useful from a mobile app perspective. These events have been overriden by the SPI and are described more thoroughly below.

##### keycloak_logins_total
This counter counts every login performed by a non-admin user. It also distinguishes logins by the utilised identity provider by means of the label **provider**.

```c
# HELP keycloak_logins_total Total successful logins
# TYPE keycloak_logins_total gauge
keycloak_logins_total{realm="test",provider="keycloak",} 3.0
keycloak_logins_total{realm="test",provider="github",} 2.0
```

##### keycloak_failed_login_attempts_total
This counter counts every login performed by a non-admin user that fails, being the error described by the label **error**. It also distinguishes logins by the identity provider used by means of the label **provider**.

```c
# HELP keycloak_failed_login_attempts_total Total failed login attempts
# TYPE keycloak_failed_login_attempts_total gauge
keycloak_failed_login_attempts_total{realm="test",provider="keycloak",error="invalid_user_credentials"} 6.0
keycloak_failed_login_attempts_total{realm="test",provider="keycloak",error="user_not_found"} 2.0
```

##### keycloak_registrations_total
This counter counts every new user registration. It also distinguishes registrations by the identity provider used by means of the label **provider**.

```c
# HELP keycloak_registrations_total Total registered users
# TYPE keycloak_registrations_total gauge
keycloak_registrations_total{realm="test",provider="keycloak",} 1.0
keycloak_registrations_total{realm="test",provider="github",} 1.0
```

##### keycloak_request_duration
This histogram records the response times per route and http method and puts them in one of five buckets:

* Requests that take 2ms or less
* Requests that take 10ms or less
* Requests that take 100ms or less
* Requests that take 1s or less
* Any request that takes longer than 1s

The response from this type of metrics has the following format:

```c
# HELP keycloak_request_duration Request duration
# TYPE keycloak_request_duration histogram
keycloak_request_duration_bucket{method="PUT",route="/admin/realms/openshift/clients/3scale",le="2.0",} 0.0
keycloak_request_duration_bucket{method="PUT",route="/admin/realms/openshift/clients/3scale",le="10.0",} 1.0
keycloak_request_duration_bucket{method="PUT",route="/admin/realms/openshift/clients/3scale",le="100.0",} 2.0
keycloak_request_duration_bucket{method="PUT",route="/admin/realms/openshift/clients/3scale",le="1000.0",} 2.0
keycloak_request_duration_bucket{method="PUT",route="/admin/realms/openshift/clients/3scale",le="+Inf",} 2.0
keycloak_request_duration_count{method="PUT",route="/admin/realms/openshift/clients/3scale",} 2.0
keycloak_request_duration_sum{method="PUT",route="/admin/realms/openshift/clients/3scale",} 83.0
```

This tells you that there have been zero requests that took less than 2ms. There was one request that took less than 10ms. All the other requests took less than 100ms.

Aside from the buckets there are also the `sum` and `count` metrics for every route and method. In the above example they tell you that there have been two requests total for this route & http method. The sum of all response times for this combination is 83ms.

To get the average request duration over the last five minutes for the whole server you can use the following Prometheus query:

```c
rate(keycloak_request_duration_sum[5m]) / rate(keycloak_request_duration_count[5m])
```

##### keycloak_response_errors_total
This counter counts the number of response errors (responses where the http status code is in the 400 or 500 range).

```c
# HELP keycloak_response_errors_total Total number of error responses
# TYPE keycloak_response_errors_total counter
keycloak_response_errors_total{code="500",method="GET",route="/",} 1
```
