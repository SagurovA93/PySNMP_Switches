use switch_snmp_lldp_t1;
select * from vlan_table 
inner join requests using(id_requests)
	where id_switches = '1' 
    and id_requests = (select max(id_requests) from (
		select id_requests from vlan_table
		WHERE id_switches = '1' ) as tmp
	);