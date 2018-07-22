use switch_snmp_lldp_t1;
select * from statistics_switch
inner join requests using(id_requests)
	where id_switches = '19' 
    and id_requests = (select max(id_requests) from (
		select id_requests from statistics_switch
		WHERE id_switches = '19' ) as tmp
	);