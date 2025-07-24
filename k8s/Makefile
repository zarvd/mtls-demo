NAMESPACE ?= cert-manager

helm-charts:
	helm repo add jetstack https://charts.jetstack.io
	helm repo update
	
install-cert-manager:
	helm upgrade cert-manager jetstack/cert-manager \
		--install \
		--namespace $(NAMESPACE) \
		--create-namespace \
		--set crds.enabled=true \
		--set disableAutoApproval=true

install-approver-policy:
	helm upgrade cert-manager-approver-policy jetstack/cert-manager-approver-policy \
		--install \
		--namespace $(NAMESPACE) \
		--wait

install-trust-manager:
	helm upgrade trust-manager jetstack/trust-manager \
		--install \
		--namespace $(NAMESPACE) \
		--create-namespace \
		--wait \
		--set app.trust.namespace=$(NAMESPACE) \
		--set app.webhook.tls.approverPolicy.enabled=true \
		--set app.webhook.tls.approverPolicy.certManagerNamespace=$(NAMESPACE)

apply:
	kubectl apply -f ./cert-manager
	kubectl apply -f ./server/namespace.yaml
	kubectl apply -f ./server
	kubectl apply -f ./client/namespace.yaml
	kubectl apply -f ./client

clean:
	kubectl delete -f ./server
	kubectl delete -f ./client
	kubectl delete -f ./cert-manager
