#include <catch2/catch_test_macros.hpp>
#include <shadow/observability/metrics.hpp>
#include <shadow/core/error.hpp>
#include <thread>

namespace obs = shadow::observability;
TEST_CASE("metrics expose counters gauges cumulative histograms and configured identities") {
    obs::Metrics metrics(obs::Role::gateway, {"home-server"});
    metrics.http_started(); metrics.http_finished({200, 0.01, 7, 11});
    metrics.http_started(); metrics.http_finished({504, 0.5, 0, 16});
    metrics.tunnel_started(); metrics.tunnel_up("home-server");
    metrics.tunnel_started(); metrics.tunnel_finished({false, "home-server", "duplicate_agent_session"});
    metrics.tunnel_bytes(true, 120); metrics.tunnel_bytes(false, 80);
    metrics.https_connection(true); metrics.https_connection(false);
    metrics.budget(obs::Budget::http, 16, 32, 64);
    metrics.event(obs::Event::backpressure); metrics.routes(2); metrics.scrape();
    const auto text = metrics.render();
    for (const auto* expected : {"shadownet_http_requests_total 2\n", "shadownet_http_in_flight 0\n", "shadownet_http_completed_total 2\n",
            "shadownet_http_request_body_bytes_total 7\n", "shadownet_http_response_body_bytes_total 27\n",
            "shadownet_http_responses_total{status_class=\"5xx\"} 1\n", "shadownet_http_request_duration_seconds_bucket{le=\"0.005\"} 0\n",
            "shadownet_http_request_duration_seconds_bucket{le=\"0.01\"} 1\n", "shadownet_http_request_duration_seconds_bucket{le=\"+Inf\"} 2\n",
            "shadownet_http_request_duration_seconds_sum 0.51\n", "shadownet_http_request_duration_seconds_count 2\n",
            "shadownet_tunnels_active 1\n", "shadownet_tunnel_connections_active 1\n", "shadownet_agent_up{agent=\"home-server\"} 1\n",
            "shadownet_tunnel_bytes_total{direction=\"sent\"} 120\n", "shadownet_tunnel_bytes_total{direction=\"received\"} 80\n",
            "shadownet_buffer_peak_bytes{scope=\"http\"} 32\n", "shadownet_routes_active 2\n", "shadownet_metrics_scrapes_total 1\n"}) CHECK(text.find(expected) != std::string::npos);
    metrics.tunnel_finished({true, "home-server", "credential_validation_failed"});
    const auto stopped = metrics.render();
    CHECK(stopped.find("shadownet_agent_up{agent=\"home-server\"} 0\n") != std::string::npos);
    CHECK(stopped.find("shadownet_tunnels_active 0\n") != std::string::npos);
    CHECK(stopped.find("shadownet_tunnel_closures_total{reason=\"credentials\"} 1\n") != std::string::npos);
}
TEST_CASE("HTTP observation ends once on completion or cancellation and survives its creator") {
    auto metrics = std::make_shared<obs::Metrics>(obs::Role::agent);
    {
        obs::HttpObservation completed(metrics);
        completed.request_bytes(3); completed.finish(204, 0); completed.finish(500, 99);
    }
    { obs::HttpObservation cancelled(metrics); cancelled.request_bytes(5); }
    const auto text = metrics->render();
    CHECK(text.find("shadownet_http_requests_total 2\n") != std::string::npos);
    CHECK(text.find("shadownet_http_completed_total 1\n") != std::string::npos);
    CHECK(text.find("shadownet_http_aborted_total 1\n") != std::string::npos);
    CHECK(text.find("shadownet_http_in_flight 0\n") != std::string::npos);
    CHECK(text.find("shadownet_http_request_body_bytes_total 8\n") != std::string::npos);
    auto retained = std::make_unique<obs::HttpObservation>(metrics);
    metrics.reset(); retained->finish(200, 1); retained.reset();
}
TEST_CASE("metric cardinality is bounded and request inputs cannot create agent labels") {
    for (const auto* name : {"bad\"name", "secret\nline", "path/agent", ""}) CHECK_THROWS_AS(obs::Metrics(obs::Role::gateway, {name}), shadow::Error);
    CHECK_THROWS_AS(obs::Metrics(obs::Role::gateway, {"same", "same"}), shadow::Error);
    std::vector<std::string> names;
    for (int i = 0; i < 1024; ++i) names.push_back("agent" + std::to_string(i) + std::string(50, 'x'));
    obs::Metrics metrics(obs::Role::gateway, names);
    metrics.tunnel_started(); metrics.tunnel_up("unknown-request-name");
    metrics.tunnel_finished({true, "unknown-request-name", "secret-query-reason"});
    const auto text = metrics.render();
    CHECK(text.size() < 262144);
    CHECK(text.find("unknown-request-name") == std::string::npos);
    CHECK(text.find("secret-query-reason") == std::string::npos);
    names.push_back("too-many");
    CHECK_THROWS_AS(obs::Metrics(obs::Role::gateway, names), shadow::Error);
}
TEST_CASE("concurrent observations preserve monotonic counters and balanced gauges") {
    auto metrics = std::make_shared<obs::Metrics>(obs::Role::gateway);
    std::vector<std::thread> workers;
    for (int n = 0; n < 4; ++n) workers.emplace_back([metrics] {
        for (int i = 0; i < 100; ++i) { obs::HttpObservation observation(metrics); observation.request_bytes(3); observation.finish(200, 5); }
    });
    for (auto& worker : workers) worker.join();
    const auto text = metrics->render();
    CHECK(text.find("shadownet_http_requests_total 400\n") != std::string::npos);
    CHECK(text.find("shadownet_http_completed_total 400\n") != std::string::npos);
    CHECK(text.find("shadownet_http_in_flight 0\n") != std::string::npos);
    CHECK(text.find("shadownet_http_request_body_bytes_total 1200\n") != std::string::npos);
}
