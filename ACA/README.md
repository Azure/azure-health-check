# Azure Container Apps and Container Apps Environment Check

The Azure Container Apps Health Check is a tool that helps you to assess the
health of your Azure Container Apps and their environments.

## ACA Environment - Checks implemented

| Category   | Check               | Explanation                                                                                                   | Guidance                                                                                                                         |
| ---------- | ------------------- | ------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| Resiliency | AvailabilityZones   | Azure Container Apps Environment should be deployed across multiple availability zones for high availability. | https://learn.microsoft.com/en-us/azure/reliability/reliability-azure-container-apps?tabs=azure-cli                              |
| Private    | DisablePublicAccess | Azure Container Apps Environment should be deployed with public access disabled.                              | https://learn.microsoft.com/en-us/azure/container-apps/vnet-custom-internal?tabs=bash&pivots=azure-portal                        |
| Security   | MTLS                | Azure Container Apps Environment should be deployed with mutual TLS enabled for internal traffic.             | https://learn.microsoft.com/en-us/azure/container-apps/networking?tabs=workload-profiles-env%2Cazure-cli#peer-to-peer-encryption |

## ACA - Checks implemented

| Category    | Check                                          | Explanation                                                                                    | Guidance                                                                                   |
| ----------- | ---------------------------------------------- | ---------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------ |
| Performance | DisableSessionAffinity                         | Azure Container Apps should be deployed with session affinity disabled for better performance. | https://learn.microsoft.com/en-us/azure/container-apps/sticky-sessions?pivots=azure-portal |
| Private     | DisableExternalIngress                         | Azure Container Apps should be deployed with external ingress disabled for better security.    | https://learn.microsoft.com/en-us/azure/container-apps/ingress-overview                    |
| Security    | DisableInsecureIngress                         | Azure Container Apps should be deployed with insecure ingress disabled for better security.    | https://learn.microsoft.com/en-us/azure/container-apps/ingress-how-to                      |
| Security    | ApplyIPSecurityRestrictionsIfExposedExternally | Azure Container Apps with external ingress should have IP security restrictions applied.       | https://learn.microsoft.com/en-us/azure/container-apps/ip-restrictions                     |
| Identity    | UseManagedIdentity                             | Azure Container Apps should be deployed with managed identity (user and/or system assigned).   | https://learn.microsoft.com/en-us/azure/container-apps/managed-identity                    |
