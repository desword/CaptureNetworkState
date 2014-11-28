package com.example.tcpdumptry;

public class MetricsOfRTT {

	public double timeOfRTT;//RTT
	public TcpFlowTuple tcpflowTuple;//tcp的源目的流
	public String RecordTime;//该RTT的时间
	
	//记录某一时段的RTT。
	//record  RTT of a time of specific iptuple 
	//[Attention!]maybe need check var is valide
	public MetricsOfRTT(double timeOfRTT,TcpFlowTuple tcpflowTuple ,String RecordTime)
	{
		this.timeOfRTT = timeOfRTT;
		this.tcpflowTuple = tcpflowTuple;
		this.RecordTime = RecordTime;
	}
	
	public String printRTT()
	{
		return "HappenTime:" + RecordTime + "-- TcpFlow:" + tcpflowTuple.printTcpFlow() + "-- RTT:" + timeOfRTT;
	}
}
