package com.example.tcpdumptry;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.Date;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import android.os.Bundle;
import android.app.Activity;
import android.content.Context;
import android.view.Menu;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;

public class MainActivity extends Activity {
	
	private TextView tc;
	private final String TcpDumpSrc = "tcpdump";
	private final String TcpDumpDst = getFilesDir() + "/tcpdump";
	
	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_main);
	    tc = (TextView)findViewById(R.id.txtView);
	    Button bt = (Button)findViewById(R.id.btnStop);
	    Button btStart = (Button)findViewById(R.id.btnStart);
	    Button btGather = (Button)findViewById(R.id.btnGatherInfo);
	    
	    bt.setOnClickListener(new OnClickListener()
	    {
	    	public void onClick(View v)
	    	{
	    		copyFile(TcpDumpSrc,TcpDumpDst);
	    		StopCapture();
	    	}
	    });	    
	    btStart.setOnClickListener(new OnClickListener()
	    {
	    	public void onClick(View v)
	    	{
	    		copyFile(TcpDumpSrc,TcpDumpDst);
	    		StartCapture();
	    	}
	    });
	    btGather.setOnClickListener(new OnClickListener()
	    {
	    	public void onClick(View v)
	    	{
	    		copyFile(TcpDumpSrc,TcpDumpDst);
	    		//System.out.println(new Date().getTime());
	    		mainGather();
	    		//System.out.println(new Date().getTime());
	    	}
	    });
	   
	    copyFile(TcpDumpSrc,TcpDumpDst);
	    //tc.append("\n"+getFilesDir() + ";\n" + getPackageCodePath());
	}
	
	//将asset下的tcpdump拷贝到 /data/data/com.example.tcpdumptry/files下面
	public void copyFile(String oldPath,String newPath)
	{
		InputStream is;
		File f;
		try {
			is = getAssets().open(oldPath);
			f =new File(newPath);
			if(f.exists())
			{
				System.out.println("cunzai!!");
				return;
			}
			FileOutputStream fos = new FileOutputStream(f);  
	        byte[] buffer = new byte[1024];  
	        int byteCount=0;                 
	        while((byteCount=is.read(buffer))!=-1) {//循环从输入流读取 buffer字节          
	            fos.write(buffer, 0, byteCount);//将读取的输入流写入到输出流  
	        }  
	        fos.flush();//刷新缓冲区  
	        is.close();  
	        fos.close(); 
	        
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}  
        
	}
	
	
	//获取metrics信息
	public void mainGather()
	{
		int i;
		String TcpDumpContent = getOutPut(TcpDumpDst + " -r /sdcard/capture.pcap \n");
		TcpMetrics tm = new TcpMetrics(TcpDumpContent.split("\\|"));
		
		for(i=0 ; i< tm.getTimeOfRTT().size() ; i++)
		{
			//System.out.println(tm.getTimeOfRTT().get(i).printRTT());
			tc.append(tm.getTimeOfRTT().get(i).printRTT());
		}		
		tc.append("[retrans]:" + tm.getNumOfRetrans());
		tc.append("\n[throughout]:" + tm.getThroughOut() + "KB/s");
		
	}
	
	//kill the process also need 'su'
	//using the output of the 'ps'
	public void StopCapture()
	{
		String[] psContent = getOutPut("ps").split("\\|");
		int i;
		for(i=0 ; i<psContent.length && psContent[i].indexOf(TcpDumpDst) == -1;i++);
		if( i== psContent.length )
		{
			System.out.println("没有启动 tcpdump进程,out");
			return;//如果没有这个进程，直接跳过
		}
        String reg = "shell {1,5}[0-9]{1,}";
        String tcpdumpPid = "";
        Matcher matcher = Pattern.compile(reg).matcher(psContent[i]);
        if (matcher.find()) {// matcher.matchers() {
        	tcpdumpPid = matcher.group().substring(10, matcher.group().length()); 
        }
        else
        {
        	System.out.println("没有find  tcpdump进程,out");
			return;//如果没有这个进程，直接跳过
        }
		
		
		Runtime runtime = Runtime.getRuntime();
    	try {
    	//	System.out.println("---------------------------->"+getPid);
			Process pro = runtime.exec("su");
	    	DataOutputStream os = new DataOutputStream(pro.getOutputStream());
	    	
	    	os.writeBytes("kill "+ tcpdumpPid + "\n");
	    	//os.flush();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}	
	}
	
	//but read the pcap file don't need the 'su'
	//so we can just execute it!!
	//[getFilesDir() + "/tcpdump -r /sdcard/capture.pcap \n"]-->read the pcap
	//use '|' to split
	public String getOutPut(String cmd)
	{
		String line = ""; 
        InputStream is = null; 
        StringBuffer sB = new StringBuffer();
        try { 
            Runtime runtime = Runtime.getRuntime(); 
            Process proc = runtime.exec(cmd); 	           
       
            is = proc.getInputStream();      
            // 换成BufferedReader 
            BufferedReader buf = new BufferedReader(new InputStreamReader(is)); 
            do { 
	           	 line = buf.readLine();
	           	 if(line == null)
	           		 break;
	           	 sB.append(line  + "|");
            } while (true); 
     
            if (is != null) { 
                buf.close(); 
                is.close(); 
            } 
        } catch (IOException e) { 
            e.printStackTrace(); 
        } 
        return sB.toString();
	}
	
	//start capture packet,and it need the root per with 'su'
	public void StartCapture()
	{
		Runtime runtime = Runtime.getRuntime();
    	Process pro;
		try {
			pro = runtime.exec("su");
			DataOutputStream os = new DataOutputStream(pro.getOutputStream());
	    	os.writeBytes("chmod 777 " + TcpDumpDst + "\n");
	    	os.writeBytes(TcpDumpDst + " -p -s 0 -w /sdcard/capture.pcap \n");//非混杂模式，绝对编号，
	    	os.flush();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}	      	
	}
	
	
	@Override
	public boolean onCreateOptionsMenu(Menu menu) {
		// Inflate the menu; this adds items to the action bar if it is present.
		getMenuInflater().inflate(R.menu.main, menu);
		return true;
	}

}
