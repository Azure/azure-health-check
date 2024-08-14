# SQL Server and Database Health Check

The SQL Server and Database Health Check is a tool that helps you to assess the
health of your SQL Server and Database.

## Server - Checks implemented

| Category    | Check                      | Explanation                                                                                        | Guidance                                                                                             |
| ----------- | -------------------------- | -------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------- |
| Auth  | EntraIDIntegrated                | The server should be integrated with EntraID for authentication and authorization.                                    |  https://learn.microsoft.com/en-us/azure/azure-sql/database/authentication-aad-configure?view=azuresql&tabs=azure-powershell                                     |
| Compliance  | Auditing          | The server should have auditing enabled.                        | https://learn.microsoft.com/en-us/azure/azure-sql/database/auditing-setup?view=azuresql                                     |
| Networking  | MinimumTLS1.2              | The server should have TLS 1.2 enabled.                                                | https://learn.microsoft.com/en-us/azure/azure-sql/database/connectivity-settings?view=azuresql&tabs=azure-portal#minimal-tls-version                                |
| Networking  | NetworkAccess                     | The server should have public network access disabled.                                                          |  https://learn.microsoft.com/en-us/azure/azure-sql/database/connectivity-settings?view=azuresql&tabs=azure-portal       |
| Networking     | OutboundNetworkAccess                    | The server should have restrictions on outbound network access disabled.                                                                   |  https://learn.microsoft.com/en-us/azure/azure-sql/database/outbound-firewall-rule-overview                                        |
| Networking     | PrivateEndpointConnections                       | The server should have private endpoint connections enabled.                                               | https://learn.microsoft.com/en-us/azure/azure-sql/database/private-endpoint-overview?view=azuresql       |
| Networking     | MaxFirewallRules       | The server should have no more than 10 firewall rules enabled.                                          | https://learn.microsoft.com/en-us/azure/azure-sql/database/firewall-configure?view=azuresql                                              |
| Networking     | MaxFirewallIPRange       | If public access is allowed via selected networks then the server should have up to 10 IPs enabled.                                            |https://learn.microsoft.com/en-us/azure/azure-sql/database/firewall-configure?view=azuresql                      |

## Database - Checks implemented

| Category    | Check             | Explanation                                                                 | Guidance                                                                                             |
| ----------- | ----------------- | --------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------- |
| Compliance  | Auditing          | The database should have auditing enabled.                        | https://learn.microsoft.com/en-us/azure/azure-sql/database/auditing-setup?view=azuresql                                         |
| Compliance     | DataUsage                       | The database must not surpass its data usage, otherwise moving to another tier is advisable.                                                            | https://learn.microsoft.com/en-us/azure/azure-sql/database/purchasing-models?view=azuresql |
| Compliance     | AutoPauseDelay       | If database is serverless then autopausedelay can be enabled.                                           |  https://learn.microsoft.com/en-us/azure/azure-sql/database/serverless-tier-overview?view=azuresql-db&tabs=general-purpose                                              |
| Data Management     | BackUps       | The database should have backups implemented.                                             | https://learn.microsoft.com/en-us/azure/azure-sql/database/automated-backups-overview?view=azuresql-db              |
| Data Management     | Replicas                   | The database should have replicas in place.                                                | https://learn.microsoft.com/en-us/azure/azure-sql/database/active-geo-replication-configure-portal?view=azuresql-db&tabs=portal                                    |
| Data Management     | TDE                 | The database should have encryption on.                                       | https://learn.microsoft.com/en-us/azure/azure-sql/database/transparent-data-encryption-byok-database-level-overview?view=azuresql                                         |