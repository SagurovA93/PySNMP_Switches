use switch_snmp_lldp_t1;
select * from 
				ports inner join 
				LLDP_table using(id_ports) inner join 
				requests using(id_requests) 
				WHERE id_switches = '1' 
                and id_requests = (select max(id_requests) from (
					select * from 
						ports inner join 
						statistics_ports using(id_ports) inner join 
						requests using(id_requests) 
						WHERE id_switches = '1' ) 
                        as tmp
	);