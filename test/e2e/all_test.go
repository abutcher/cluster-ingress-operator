//go:build e2e
// +build e2e

package e2e

import "testing"

// TestAll is the entrypoint for `make test-e2e` unless you override
// with: make TEST=Test<foo> test-e2e.
//
// The overriding goal of this test is to run as many tests in
// parallel as possible before running those tests that must run serially. There
// are two goals: 1) cut down on test execution time and 2) provide
// explicit ordering for tests that do not expect a rolling update of
// ingresscontroller pods because a previous test modified the
// ingressconfig object and the defer logic for cleanup is still
// runnng when the new test starts.
func TestAll(t *testing.T) {
	// This call to Run() will not return until all of its
	// parallel subtests complete. Each "parallel" test must
	// invoke t.Parallel().
	t.Run("parallel", func(t *testing.T) {
		t.Run("TestAWSELBConnectionIdleTimeout", TestAWSELBConnectionIdleTimeout)
		t.Run("TestClientTLS", TestClientTLS)
		t.Run("TestContainerLogging", TestContainerLogging)
		t.Run("TestCreateIngressControllerThenSecret", TestCreateIngressControllerThenSecret)
		t.Run("TestCreateSecretThenIngressController", TestCreateSecretThenIngressController)
		t.Run("TestCustomErrorpages", TestCustomErrorpages)
		t.Run("TestCustomIngressClass", TestCustomIngressClass)
		t.Run("TestDomainNotMatchingBase", TestDomainNotMatchingBase)
		t.Run("TestDynamicConfigManagerUnsupportedConfigOverride", TestDynamicConfigManagerUnsupportedConfigOverride)
		t.Run("TestForwardedHeaderPolicyAppend", TestForwardedHeaderPolicyAppend)
		t.Run("TestForwardedHeaderPolicyIfNone", TestForwardedHeaderPolicyIfNone)
		t.Run("TestForwardedHeaderPolicyNever", TestForwardedHeaderPolicyNever)
		t.Run("TestForwardedHeaderPolicyReplace", TestForwardedHeaderPolicyReplace)
		t.Run("TestHAProxyTimeouts", TestHAProxyTimeouts)
		t.Run("TestHAProxyTimeoutsRejection", TestHAProxyTimeoutsRejection)
		t.Run("TestHTTPCookieCapture", TestHTTPCookieCapture)
		t.Run("TestHTTPHeaderBufferSize", TestHTTPHeaderBufferSize)
		t.Run("TestHTTPHeaderCapture", TestHTTPHeaderCapture)
		t.Run("TestHeaderNameCaseAdjustment", TestHeaderNameCaseAdjustment)
		t.Run("TestHealthCheckIntervalIngressController", TestHealthCheckIntervalIngressController)
		t.Run("TestHostNetworkEndpointPublishingStrategy", TestHostNetworkEndpointPublishingStrategy)
		t.Run("TestIngressControllerScale", TestIngressControllerScale)
		t.Run("TestIngressControllerServiceNameCollision", TestIngressControllerServiceNameCollision)
		t.Run("TestInternalLoadBalancer", TestInternalLoadBalancer)
		t.Run("TestInternalLoadBalancerGlobalAccessGCP", TestInternalLoadBalancerGlobalAccessGCP)
		t.Run("TestLoadBalancingAlgorithmUnsupportedConfigOverride", TestLoadBalancingAlgorithmUnsupportedConfigOverride)
		t.Run("TestLocalWithFallbackOverrideForNodePortService", TestLocalWithFallbackOverrideForNodePortService)
		t.Run("TestNetworkLoadBalancer", TestNetworkLoadBalancer)
		t.Run("TestNodePortServiceEndpointPublishingStrategy", TestNodePortServiceEndpointPublishingStrategy)
		t.Run("TestProxyProtocolAPI", TestProxyProtocolAPI)
		t.Run("TestReloadIntervalUnsupportedConfigOverride", TestReloadIntervalUnsupportedConfigOverride)
		t.Run("TestRouteAdmissionPolicy", TestRouteAdmissionPolicy)
		t.Run("TestRouterCompressionParsing", TestRouterCompressionParsing)
		t.Run("TestScopeChange", TestScopeChange)
		t.Run("TestSyslogLogging", TestSyslogLogging)
		t.Run("TestTLSSecurityProfile", TestTLSSecurityProfile)
		t.Run("TestTunableMaxConnectionsInvalidValues", TestTunableMaxConnectionsInvalidValues)
		t.Run("TestTunableMaxConnectionsValidValues", TestTunableMaxConnectionsValidValues)
		t.Run("TestTunableRouterKubeletProbesForCustomIngressController", TestTunableRouterKubeletProbesForCustomIngressController)
		t.Run("TestUniqueDomainRejection", TestUniqueDomainRejection)
		t.Run("TestUniqueIdHeader", TestUniqueIdHeader)
		t.Run("TestUserDefinedIngressController", TestUserDefinedIngressController)
		t.Run("TestIngressOperatorCacheIsNotGlobal", TestIngressOperatorCacheIsNotGlobal)
		t.Run("TestDeleteIngressControllerShouldClearRouteStatus", TestDeleteIngressControllerShouldClearRouteStatus)
		t.Run("TestIngressControllerRouteSelectorUpdateShouldClearRouteStatus", TestIngressControllerRouteSelectorUpdateShouldClearRouteStatus)
		t.Run("TestIngressControllerNamespaceSelectorUpdateShouldClearRouteStatus", TestIngressControllerNamespaceSelectorUpdateShouldClearRouteStatus)
	})

	t.Run("serial", func(t *testing.T) {
		t.Run("TestDefaultIngressControllerSteadyConditions", TestDefaultIngressControllerSteadyConditions)
		t.Run("TestClusterOperatorStatusRelatedObjects", TestClusterOperatorStatusRelatedObjects)
		t.Run("TestConfigurableRouteNoConsumingUserNoRBAC", TestConfigurableRouteNoConsumingUserNoRBAC)
		t.Run("TestConfigurableRouteNoSecretNoRBAC", TestConfigurableRouteNoSecretNoRBAC)
		t.Run("TestConfigurableRouteRBAC", TestConfigurableRouteRBAC)
		t.Run("TestDefaultIngressCertificate", TestDefaultIngressCertificate)
		t.Run("TestDefaultIngressClass", TestDefaultIngressClass)
		t.Run("TestHstsPolicyWorks", TestHstsPolicyWorks)
		t.Run("TestIngressControllerCustomEndpoints", TestIngressControllerCustomEndpoints)
		t.Run("TestIngressStatus", TestIngressStatus)
		t.Run("TestLocalWithFallbackOverrideForLoadBalancerService", TestLocalWithFallbackOverrideForLoadBalancerService)
		t.Run("TestOperatorSteadyConditions", TestOperatorSteadyConditions)
		t.Run("TestPodDisruptionBudgetExists", TestPodDisruptionBudgetExists)
		t.Run("TestProxyProtocolOnAWS", TestProxyProtocolOnAWS)
		t.Run("TestRouteHTTP2EnableAndDisableIngressController", TestRouteHTTP2EnableAndDisableIngressController)
		t.Run("TestRouteHardStopAfterEnableOnIngressController", TestRouteHardStopAfterEnableOnIngressController)
		t.Run("TestRouteHardStopAfterTestInvalidDuration", TestRouteHardStopAfterTestInvalidDuration)
		t.Run("TestRouteHardStopAfterTestOneDayDuration", TestRouteHardStopAfterTestOneDayDuration)
		t.Run("TestRouteHardStopAfterTestZeroLengthDuration", TestRouteHardStopAfterTestZeroLengthDuration)
		t.Run("TestRouteNbthreadIngressController", TestRouteNbthreadIngressController)
		t.Run("TestRouterCompressionOperation", TestRouterCompressionOperation)
		t.Run("TestUpdateDefaultIngressController", TestUpdateDefaultIngressController)
		t.Run("TestCanaryRoute", TestCanaryRoute)
		t.Run("TestRouteHTTP2EnableAndDisableIngressConfig", TestRouteHTTP2EnableAndDisableIngressConfig)
		t.Run("TestRouteHardStopAfterEnableOnIngressConfig", TestRouteHardStopAfterEnableOnIngressConfig)
		t.Run("TestRouteHardStopAfterEnableOnIngressControllerHasPriorityOverIngressConfig", TestRouteHardStopAfterEnableOnIngressControllerHasPriorityOverIngressConfig)
		t.Run("TestHostNetworkPortBinding", TestHostNetworkPortBinding)
	})
}
