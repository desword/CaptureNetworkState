package com.example.tcpdumptry;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class TcpMetrics {

	
	private String[] dumpContent;
	private ArrayList<MetricsOfRTT> TimeOfRTT = new ArrayList<MetricsOfRTT>();
	//[sip|dip] --> [seq]
	private HashMap<String, ArrayList<String>> DetailofRetrans = new HashMap<String,ArrayList<String>>();
	private int NumOfRetrans;
	
	//[sip|dip] --> [lastseq]
	private HashMap<String, ArrayList<String>> SendPack = new HashMap<String ,ArrayList<String>>();
	//[sip|dip] --> [count]
	private HashMap<String, ArrayList<String>> SendPackCount = new HashMap<String ,ArrayList<String>>();
	private double ThroughOut;
	//尝试利用计算吞吐量来计算重传次数
	private int sendCount;
	private int recevieCount;
	
	TcpMetrics(String[] GetdumpContent)
	{
		this.dumpContent = GetdumpContent;
		this.NumOfRetrans = 0;
		this.sendCount = this.recevieCount = 0;
		getAllRTT();
		getAllNumOfRetrans();
		getThroughOuts();
	}
	
	//获取本次抓包的吞吐量
	public void getThroughOuts()
	{
		int i;
		long packSend = 0;
		double wholeTime = getWholetime();
		TcpFlowTuple tmpTcp;
		for(i=0 ; i< dumpContent.length ; i++)
		{
			if( (tmpTcp=dragTcptup(dumpContent[i])) == null )
				continue;//过滤非tcp格式
			String otherTcpType = tmpTcp.srcIP_port + "|" + tmpTcp.dstIP_port;
			String lastSeq = getLastSeq(dumpContent[i]);
			String packCount = getPackCount(dumpContent[i]);
			String ack = getAck(dumpContent[i]);
			if(packCount != null && !packCount.equals("0"))//传输包,过滤0长度的包
				if(!SendPack.containsKey(otherTcpType))
				{
					ArrayList<String> arr = new ArrayList<String>();
					ArrayList<String> arrc = new ArrayList<String>();
					arr.add(lastSeq);
					arrc.add(packCount);
					SendPack.put(otherTcpType,arr);
					SendPackCount.put(otherTcpType, arrc);
					this.sendCount++;//发送的包计数
				}
				else
				{
					ArrayList<String> arr = SendPack.get(otherTcpType);
					ArrayList<String> arrc = SendPackCount.get(otherTcpType);
					arr.add(lastSeq); 
					arrc.add(packCount);
					this.sendCount++;//发送的包计数
				}
			if(ack != null && !ack.equals("1"))//确认包，且非确认SYN包
			{
				String reTcp = tmpTcp.dstIP_port + "|" + tmpTcp.srcIP_port;
				if(!SendPack.containsKey(reTcp))
					continue;//过滤数据包记录断掉的部分
				ArrayList<String> arr = SendPack.get(reTcp);
				ArrayList<String> arrc = SendPackCount.get(reTcp);
				int seqIndex = arr.indexOf(ack);
				if(seqIndex == -1)
					continue;//过滤没有匹配的确认包，可能数据包截断。
				String[] countAndflag = arrc.get(seqIndex).split("\\|");
				if( countAndflag.length > 1)
					continue;//过滤已经确认过的包
				packSend += (Integer.parseInt(countAndflag[0]));//增加确认的包大小
				arrc.set(seqIndex, countAndflag[0] + "|1");//标记已经确认过
				this.recevieCount++;//接受包计数
			}			
		}	
		
		//计数吞吐量--[kB/s]
		this.ThroughOut = packSend / (wholeTime * 1024);

		//System.out.println("[thOut]:" + packSend);
		System.out.println("[thOut]:" + this.ThroughOut);
		System.out.println("[send]:" + this.sendCount + "[rece]:" + this.recevieCount);
	}
	//获取整个包的传输时间
	//return -1:无法获取有效的时间段
	public double getWholetime()
	{
		int i;
		double startTime=-1,endTime=-1;
		for(i=0 ; i<dumpContent.length &&  (startTime=getTupMillTime(dumpContent[i])) ==-1 ; i++);
		for(i= dumpContent.length-1 ; i>=0 && (endTime=getTupMillTime(dumpContent[i])) == -1 ; i--);
		if( startTime == -1 || endTime == -1)
			return -1;
		return endTime-startTime;
	}
	
	
	//获取最终重传的次数
	//具体重传的包细节在DetailofRetrans中
	//[alarm!]每次使用tcpdump命令读取的pcap包内容可能不一样。？
	public void getAllNumOfRetrans()
	{
		int i;
		TcpFlowTuple tmpTcp;
		for(i=0 ; i< dumpContent.length ; i++)
		{
			tmpTcp = dragTcptup(dumpContent[i]);
			if(tmpTcp == null)//过滤掉非标准的tcpflow格式
				continue;
			String otherTcpType = tmpTcp.srcIP_port + "|" + tmpTcp.dstIP_port;
			String seq = getWholeSeq(dumpContent[i]);
			if(seq == null || dumpContent[i].indexOf("S") != -1)//过滤ack包，请求链接的包
				continue;
			if(!DetailofRetrans.containsKey(otherTcpType))//添加一个新的tcp，seq对进去
			{
				ArrayList<String> arrayStr = new ArrayList<String>();
				arrayStr.add(seq);
				DetailofRetrans.put(otherTcpType, arrayStr);
				continue;
			}
			if(isRetrans(dumpContent[i], otherTcpType,seq))
				this.NumOfRetrans++;
			else
			{
				ArrayList<String> arr = DetailofRetrans.get(otherTcpType);
				arr.add(seq);
			}			
			
		}	
	}
	//判断是否为重传包
	public boolean isRetrans(String content,String otherTcpType,String seq)
	{
		ArrayList<String> arr = DetailofRetrans.get(otherTcpType);
		if(arr.indexOf(seq) != -1) //如果找到同样的传输包序列，
		{
			System.out.println("[rTRans]:" + content);
			return true;
		}
		String first = getFirstSeq(content);
		String last = getLastSeq(arr.get(arr.size()-1));
		if(first.compareTo(last)<0)//如果出现包序号突然递减，重传
		{
			System.out.println("[rTRans]:" + content);
			return true;
		}
		return false;	
		
	}
	//获取 整个数据包seq
	public String getWholeSeq(String content)
	{
		String reg = " [0-9]{1,}:[0-9]{1,}\\([0-9]{1,}\\) "; // match pack seq
		Matcher matcher = Pattern.compile(reg).matcher(content);
        if (matcher.find()) {// matcher.matchers() {
            String fqdnId = matcher.group().substring(1, matcher.group().length()-1);
            System.out.println("[Pagseq]:" + fqdnId);
            return fqdnId;
        }
        return null;
	}
	
	
	//获取所有的RTT时间，放入list中
	public void getAllRTT()
	{
		int i;
		TcpFlowTuple rttTuple;
		for(i=0 ; i< dumpContent.length ; i++)
		{
			if(dumpContent[i].indexOf("S") != -1 && i+1< dumpContent.length)
			{
				rttTuple = dragTcptup(dumpContent[i]);
				int nextPack = (Integer.parseInt(getLastSeq(dumpContent[i]))+1);
				TimeOfRTT.add(new MetricsOfRTT(
								CaptureRtt(dumpContent,i+1,rttTuple.tupleReverse(),String.valueOf(nextPack) ),		//RTT time
								rttTuple,													//tcp flow
								dumpContent[i].substring(0, dumpContent[i].indexOf("IP")-1))//occurs time
				);
			}
		}
	}
	//对某个RTT对进行分析，并返回RTT时间
	//-1表示，或者数据包截断了，或者网络断开了，相应时间无穷大
	public double CaptureRtt(String[] dump,int StartIndex, TcpFlowTuple matchTup,String nextPackSeq)
	{
		int i = StartIndex;
		TcpFlowTuple tmpTup;
		for( ; i<dump.length ; i++)
		{
			tmpTup = dragTcptup(dump[i]);
			if(tmpTup == null)//过滤非标准tcp流格式
				continue;
			if(matchTup.isEqual(tmpTup) && 
					(dump[i].indexOf(". ack") != -1 || getPigback(dump[i]).equals(nextPackSeq) ) )//直接确认与piggy-back
			{
				return (getTupMillTime(dump[i]) - getTupMillTime(dump[StartIndex-1]));
			}			
		}
		return -1;
	}
	//获取每行数据包的tcpIp流
	//return: null,不是标准的tcp流格式
	public TcpFlowTuple dragTcptup(String content)
	{
        String reg = "IP .{1,} > .{1,}: ";
        Matcher matcher = Pattern.compile(reg).matcher(content);
        if (matcher.find()) {// matcher.matchers() {
            String fqdnId = matcher.group().substring(3, matcher.group().length()-2);
            System.out.println("[tcpflow]:" + fqdnId);
            String[] sp = fqdnId.split(" > ");
            return (new TcpFlowTuple(sp[0], sp[1]));
        }
        return null;
	}
	//获取每行数据包的秒时间
	//return -1: 不是有效的tcp包，无法获取时间
	public double getTupMillTime(String content)
	{
        String reg = ".{1,} IP";
        Matcher matcher = Pattern.compile(reg).matcher(content);
        if (matcher.find()) {// matcher.matchers() {
            String fqdnId = matcher.group().substring(0, matcher.group().length()-3);
    		String[] Times = fqdnId.split(":");
    		return Integer.parseInt(Times[0])*3600.0 + Integer.parseInt(Times[1])*60.0 + Float.valueOf(String.valueOf(Times[2]));
        }
        return -1;
	}
	//获取数据包序列的last包号
	public String getLastSeq(String content)
	{
		String reg = ":[0-9]{1,}\\(";	//match last seq
        Matcher matcher = Pattern.compile(reg).matcher(content);
        if (matcher.find()) {// matcher.matchers() {
            String fqdnId = matcher.group().substring(1, matcher.group().length()-1);
            System.out.println("[lastPag]:" + fqdnId);
            return fqdnId;
        }
        return null;
	}
	//获取数据包序列的first包号
	public String getFirstSeq(String content)
	{
	    String reg = " [0-9]{1,}:";	//match first seq
        Matcher matcher = Pattern.compile(reg).matcher(content);
        if (matcher.find()) {// matcher.matchers() {
            String fqdnId = matcher.group().substring(1, matcher.group().length()-1);
            System.out.println("[firstPag]:" + fqdnId);
            return fqdnId;
        }
        return null;
	}
	//获取包长度
	public String getPackCount(String content)
	{
        String reg = "\\([0-9]{1,}\\)";
        Matcher matcher = Pattern.compile(reg).matcher(content);
        if (matcher.find()) {// matcher.matchers() {
            String fqdnId = matcher.group().substring(1, matcher.group().length()-1);
            System.out.println("[pigcount]:" + fqdnId);
            return fqdnId;
        }
        return null;
	}
	//获取piggy-back确认的包号
	public String getPigback(String content)
	{

		String reg = "\\) ack [0-9]{1,}";
		Matcher matcher = Pattern.compile(reg).matcher(content);
        if (matcher.find()) {// matcher.matchers() {
            String fqdnId = matcher.group().substring(6, matcher.group().length());
            System.out.println("[pig]:" + fqdnId);
            return fqdnId;
        }
        return null;
	}
	//获取确认的包号
	public String getAck(String content)
	{
		String reg = ". ack [0-9]{1,}";
		Matcher matcher = Pattern.compile(reg).matcher(content);
        if (matcher.find()) {// matcher.matchers() {
            String fqdnId = matcher.group().substring(6, matcher.group().length());
            System.out.println("[ack]:" + fqdnId);
            return fqdnId;
        }
        return null;
	}
	
	
	public int getNumOfRetrans()
	{
		return NumOfRetrans;
	}
	public ArrayList<MetricsOfRTT>  getTimeOfRTT()
	{
		return TimeOfRTT;
	}
	public double getThroughOut()
	{
		return ThroughOut;
	}
}
