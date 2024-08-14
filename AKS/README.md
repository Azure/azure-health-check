# AKS Cluster and NodePool Health Check

The AKS Cluster and NodePool Health Check is a tool that helps you to assess the
health of your AKS clusters and nodepools.

## Cluster - Checks implemented

| Category    | Check                      | Explanation                                                                                        | Guidance                                                                                             |
| ----------- | -------------------------- | -------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------- |
| Resiliency  | Autoscaling                | Autoscaling should be enabled in the cluster for all nodepools.                                    | https://learn.microsoft.com/en-us/azure/aks/cluster-autoscaler                                       |
| Resiliency  | AvailabilityZones          | Availability zones should be enabled in the cluster for higher resiliency.                         | https://learn.microsoft.com/en-us/azure/aks/availability-zones                                       |
| Resiliency  | UserNodePools              | User node pools should be used in the cluster.                                                     | https://learn.microsoft.com/en-us/azure/aks/use-multiple-node-pools                                  |
| Resiliency  | Backup                     | Backups should be enabled in the cluster.                                                          | https://learn.microsoft.com/en-us/azure/backup/azure-kubernetes-service-cluster-manage-backups       |
| Resiliency  | MinNodesPerPool            | Each nodepool should have at least 3 nodes for high availability.                                  | -                                                                                                    |
| Private     | Cluster                    | The cluster should be private.                                                                     | https://learn.microsoft.com/en-us/azure/aks/private-clusters                                         |
| Private     | FQDN                       | The cluster should have a private FQDN.                                                            | https://learn.microsoft.com/en-us/azure/aks/private-clusters?tabs=azure-portal#disable-a-public-fqdn |
| Private     | NoPublicLoadBalancer       | Public load balancers should not be used in the cluster.                                           | https://learn.microsoft.com/en-us/azure/aks/internal-lb                                              |
| Network     | StandardLoadBalancer       | Standard load balancers should be used in the cluster.                                             | https://learn.microsoft.com/en-us/azure/load-balancer/load-balancer-standard-overview                |
| Network     | Policies                   | Network policies should be enabled in the cluster.                                                 | https://learn.microsoft.com/en-us/azure/aks/use-network-policies                                     |
| Network     | CNIOverlay                 | The cluster should use the Azure CNI Overlay network plugin.                                       | https://learn.microsoft.com/en-us/azure/aks/azure-cni-overlay                                        |
| Performance | EphemeralOSDisk            | Ephemeral OS disks should be used in the cluster.                                                  | https://learn.microsoft.com/en-us/samples/azure-samples/aks-ephemeral-os-disk/aks-ephemeral-os-disk/ |
| Compliance  | KubernetesVersionSupported | The Kubernetes version used in the cluster should be supported by AKS.                             | https://learn.microsoft.com/en-us/azure/aks/supported-kubernetes-versions                            |
| Compliance  | AutoUpgradeEnabled         | Auto-upgrade should be enabled in the cluster.                                                     | https://learn.microsoft.com/en-us/azure/aks/auto-upgrade-cluster                                     |
| Compliance  | SLA                        | The cluster should have a service level agreement (SLA).                                           | https://learn.microsoft.com/en-us/azure/aks/free-standard-pricing-tiers                              |
| Compliance  | AzurePolicyEnabled         | Azure Policy should be enabled in the cluster.                                                     | https://learn.microsoft.com/en-us/azure/aks/use-azure-policy                                         |
| Addon       | ContainerInsights          | Azure Monitor for containers should be enabled in the cluster.                                     | https://learn.microsoft.com/en-us/azure/azure-monitor/insights/container-insights-overview           |
| Addon       | DiagnosticSettings         | Diagnostic settings should be enabled in the cluster.                                              | https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/create-diagnostic-settings          |
| Addon       | Defender                   | Microsoft Defender for Containers should be enabled in the cluster.                                | https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-containers-introduction      |
| Addon       | KeyVaultSecretProvider     | Azure Key Vault secret provider should be used for storing and accessing secrets.                  | https://learn.microsoft.com/en-us/azure/aks/csi-secrets-store-driver                                 |
| Auth        | EntraIDIntegrated          | The cluster should be integrated with Azure Active Directory for authentication and authorization. | https://learn.microsoft.com/en-us/azure/aks/enable-authentication-microsoft-entra-id                 |
| Auth        | LocalAccountsDisbaled      | Local accounts should be disabled in the cluster.                                                  | https://learn.microsoft.com/en-us/azure/aks/manage-local-accounts-managed-azure-ad                   |
| Auth        | RBACEnabled                | Role-based access control (RBAC) should be enabled in the cluster.                                 | https://learn.microsoft.com/en-us/azure/aks/operator-best-practices-cluster-security#enable-rbac     |
| Auth        | UserAssignedIdentity       | User-assigned managed identities should be used in the cluster.                                    | https://learn.microsoft.com/en-us/azure/aks/use-managed-identity                                     |
| Auth        | WorkloadIdentities         | Workload identities should be used to authenticate to other resources.                             | https://learn.microsoft.com/en-us/azure/aks/learn/tutorial-kubernetes-workload-identity              |
| Auth        | PodIdentities              | Pod identities are deprecated and should not be used. Leverage workload identities instead.        | https://learn.microsoft.com/en-us/azure/aks/learn/tutorial-kubernetes-workload-identity              |

## NodePool - Checks implemented

| Category    | Check             | Explanation                                                                 | Guidance                                                                                             |
| ----------- | ----------------- | --------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------- |
| Resiliency  | Autoscaling       | Autoscaling should be enabled in the nodepool.                              | https://learn.microsoft.com/en-us/azure/aks/cluster-autoscaler                                       |
| Resiliency  | AvailabilityZones | Availability zones should be enabled in the nodepool for higher resiliency. | https://learn.microsoft.com/en-us/azure/aks/availability-zones                                       |
| Resiliency  | MinNodesPerPool   | For high availability, the minimum amount of nodes per pool should be 3.    | -                                                                                                    |
| Performance | EphemeralOSDisk   | Ephemeral OS disks should be used for the nodes                             | https://learn.microsoft.com/en-us/samples/azure-samples/aks-ephemeral-os-disk/aks-ephemeral-os-disk/ |
| Private     | PublicIPDisabled  | Public IP should be disabled for the nodes in the nodepool.                 | https://learn.microsoft.com/en-us/azure/aks/use-node-public-ips                                      |
