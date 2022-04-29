event http_reply(c:connection,version:string,code:count,reason:string){
	SumStats::observe("all_response",SumStats::Key(),SumStats::Observation($num=1));
	if(code==404){
		SumStats::observe("404_response",SumStats::Key(),SumStats::Observation($num=1));
		SumStats::observe("404_url",SumStats::Key($host=c$id$resp_h),SumStats::Observation($str=c$http$uri));
	}
}


event zeek_init(){
	local r1=SumStats::Reducer($stream="all_response",$apply=set(SumStats::SUM));
	local r2=SumStats::Reducer($stream="404_response",$apply=set(SumStats::SUM));
	local r3=SumStats::Reducer($stream="404_url",$apply=set(SumStats::UNIQUE));
	
	SumStats::create([$name="404 statistics",
		$epoch=10mins,
		$reducers=set(r1,r2,r3),
		$epoch_result(ts:time,key: SumStats::Key,result: SumStats::Result)={
			local rall=result["all_response"];
			local r404r=result["404_response"];
			local r404url=result["404_url"];

			if(r404r$sum>2 && r404r$sum/rall$sum>0.2 && r404url$sum/r404r$sum>0.5){
				print fmt("%s is a scanner with %s scan attemps on %s urls",key$host,r404r$num,r404url$num);
			}
		}
	]);
}
