use switch_snmp_lldp_t1;
select * from 
				ports inner join 
				FDB_tables using(id_ports) inner join 
				requests using(id_requests) 
				WHERE id_switches = '1' 
                and id_requests = (select max(id_requests) from (
					select * from 
						ports inner join 
						FDB_tables using(id_ports) inner join 
						requests using(id_requests) 
						WHERE id_switches = '1' ) 
                        as tmp
	);