helm-charts:
	helm repo add jetstack https://charts.jetstack.io
	helm repo update
	
install-cert-manager:
	helm upgrade cert-manager jetstack/cert-manager \
		--install \
		--namespace cert-manager \
		--create-namespace \
		--set crds.enabled=true \
		--set disableAutoApproval=true

install-approver-policy:
	helm upgrade cert-manager-approver-policy jetstack/cert-manager-approver-policy \
		--install \
		--namespace cert-manager \
		--wait
