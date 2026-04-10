output "hub_vnet_id" {
  value = module.hub_vnet.hub_vnet_id
}

output "vnet1_id" {
  value = module.vnet1.vnet1_id
}

output "vnet2_id" {
  value = module.vnet2.vnet2_id
}

output "vnet3_id" {
  value = module.vnet3.vnet3_id
}

output "vm1_public_ip" {
  description = "Visit DVWA at http://<ip>/dvwa"
  value       = module.vm1_webserver.vm1_public_ip
}

output "sql_server_fqdn" {
  value = module.sql_database.sql_server_fqdn
}

output "sql_server_name" {
  value = module.sql_database.sql_server_name
}

output "sql_database_name" {
  value = module.sql_database.sql_database_name
}

output "linux_syslog_dcr_id" {
  value = module.sentinel.linux_syslog_dcr_id
}


output "soar_email_alert_id" {
  value = module.soar.soar_email_alert_id
}

output "soar_ban_attacker_id" {
  value = module.soar.soar_ban_attacker_id
}