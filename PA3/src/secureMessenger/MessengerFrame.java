// Samuel Davidson
// https://github.com/samdamana

package secureMessenger;

import java.awt.BorderLayout;
import java.awt.Container;
import java.awt.Dimension;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.IOException;

import javax.swing.JButton;
import javax.swing.JScrollPane;
import javax.swing.JTextField;
import javax.swing.JTextArea;
import javax.swing.JFrame;
import javax.swing.JMenuBar;
import javax.swing.JOptionPane;
import javax.swing.WindowConstants;

public class MessengerFrame implements ActionListener {
	
	//Connecting
	private JMenuBar menuBar;
	private JButton connectButton;
	private JButton hostButton;
	private JTextField addressBox;
	private JTextField portBox;
	
	//Actual message exchange stuff
	private JTextArea outputArea;
	private JTextField inputBox;
	private JButton sendButton;
	
	//Cryptography
	private SecureMessenger messenger;
	
	public static void main(String[] args) 
	{
		MessengerFrame mf = new MessengerFrame();
	}
	
	public MessengerFrame() 
	{
		//Create the main frame.
		JFrame myFrame = new JFrame("Secure Messenger");
		myFrame.setSize(300,400);
		myFrame.setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);
		
		menuBar = new JMenuBar();
		
		connectButton = new JButton("Connect");
		connectButton.addActionListener(this);
		hostButton = new JButton("Host");
		hostButton.addActionListener(this);
		addressBox = new JTextField("Address");
		portBox = new JTextField("Port");
		
		menuBar.add(connectButton);
		menuBar.add(hostButton);
		menuBar.add(addressBox);
		menuBar.add(portBox);
		
		myFrame.setJMenuBar(menuBar);
		
		outputArea = new JTextArea("Input port and click 'Host'\nOr\nInput address and port and click 'Connect'\n");
		outputArea.setMinimumSize(new Dimension(300,200));
		outputArea.setEditable(false);
		JScrollPane scrollArea = new JScrollPane(outputArea);
		
		inputBox = new JTextField();
		inputBox.setEnabled(false);
		sendButton = new JButton("Send");
		sendButton.addActionListener(this);
		sendButton.setMaximumSize(new Dimension(100,50));
		sendButton.setEnabled(false);
		
		Container inputSendContainer = new Container();
		inputSendContainer.setLayout(new BorderLayout());
		inputSendContainer.add(inputBox, BorderLayout.CENTER);
		inputSendContainer.add(sendButton, BorderLayout.EAST);
		
		myFrame.getContentPane().add(scrollArea, BorderLayout.CENTER);
		myFrame.getContentPane().add(inputSendContainer, BorderLayout.SOUTH);
		
		myFrame.setResizable(false);
		
		messenger = new SecureMessenger(this);
		myFrame.setVisible(true);
	}

	@Override
	public void actionPerformed(ActionEvent e) 
	{
		if(e.getSource() == connectButton)
		{
			OutputPrintln("Connect");
		}
		else if(e.getSource() == hostButton)
		{
			int port;
			try
			{
				port = Integer.parseInt(portBox.getText());
			}
			catch(NumberFormatException exc)
			{
				MessageBox("Unable to parse port number.", "Port Error");
				return;
			}
			if(port < 1023 || port > 65535)
			{
				MessageBox("Invalid port chosen. Port must be between 1023 and 65535.", "Port Error");
				return;
			}
			try 
			{
				messenger.ServerSetup(port);
			} catch (IOException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
		}
		else if(e.getSource() == sendButton)
		{
			OutputPrintln("Send");
		}
	}
	
	public void OutputPrintln(String str) 
	{
		outputArea.append(str + "\n");
	}
	
	/**
	 * Not my code. Thank you Sebastian Troy
	 * Creates an info box that controls focus until acknowledged. 
	 * http://stackoverflow.com/questions/7080205/popup-message-boxes
	 * @param infoMessage
	 * @param titleBar
	 */
	public static void MessageBox(String infoMessage, String titleBar)
    {
        JOptionPane.showMessageDialog(null, infoMessage, "InfoBox: " + titleBar, JOptionPane.INFORMATION_MESSAGE);
    }

}