package conf

func init() {
	RegisterConfigureFilePostProcessingStage("FakeDNS", &FakeDNSPostProcessingStage{})
	RegisterConfigureFilePostProcessingStage("Subscription", &SubscriptionPostProcessingStage{})
}
