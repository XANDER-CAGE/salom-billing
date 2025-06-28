-record(ipt_args, {sec, src_ip, dst_ip, src_port, dst_port, proto, octets, dir}).

-record(ipt_session, {
	  sid,
	  cid,
	  uuid,
	  ip,
	  username,
	  status,
	  started_at,
	  expires_at,
	  finished_at,
	  pid,
	  node,
	  nas_spec,
	  disc_req_sent,
	  shaper,
	  data
	 }).
