package com.example.tcpdumptry;

public class TcpFlowTuple {
	public String srcIP_port;
	public String dstIP_port;

	
	//tcpflow tuple. 
	public TcpFlowTuple(String src,String dst)
	{
		this.srcIP_port = src;
		this.dstIP_port = dst;
	}
	public boolean isEqual(TcpFlowTuple tu1)
	{
		if(tu1.srcIP_port.equals(srcIP_port )&& tu1.dstIP_port.equals(dstIP_port))
			return true;
		return false;
	}
	public TcpFlowTuple tupleReverse()
	{
		return (new TcpFlowTuple(dstIP_port,srcIP_port));	
	}
	public String printTcpFlow()
	{
		return "[" + srcIP_port + ">" + dstIP_port + "]";
	}
}
