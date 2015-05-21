// Samuel Davidson
// https://github.com/samdamana

package secureMessenger;

import java.awt.BorderLayout;
import java.awt.Container;
import java.awt.Dimension;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.JButton;
import javax.swing.JScrollPane;
import javax.swing.JTextField;
import javax.swing.JTextArea;
import javax.swing.JFrame;
import javax.swing.JMenuBar;
import javax.swing.JOptionPane;
import javax.swing.SwingUtilities;
import javax.swing.WindowConstants;

public class MessengerFrame implements ActionListener {
	
	//Connecting
	private JMenuBar menuBar;
	private JButton connectButton;
	private JButton hostButton;
	private JTextField addressBox;
	private JTextField portBox;
	
	//Actual message exchange stuff
	JTextArea outputArea;
	private JTextField inputBox;
	private JButton sendButton;
	
	//Cryptography
	private SecureMessenger messenger;
	private Thread messengerThread;
	
	public static void main(String[] args) 
	{
		new MessengerFrame();
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
		addressBox = new JTextField("localhost");
		portBox = new JTextField("3210");
		
		menuBar.add(connectButton);
		menuBar.add(hostButton);
		menuBar.add(addressBox);
		menuBar.add(portBox);
		
		myFrame.setJMenuBar(menuBar);
		
		outputArea = new JTextArea();
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
		outputArea.append("\nInput port and click 'Host'\nOr\nInput address and port and click 'Connect'\n");
		
		myFrame.setVisible(true);
	}

	@Override
	public void actionPerformed(ActionEvent e) 
	{
		if(e.getSource() == connectButton)
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
			messenger.isHost = false;
			messenger.port = port;
			messenger.host = addressBox.getText();
			messengerThread = new Thread(messenger, "Secure Messenger Client");
			messengerThread.start();
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
			messenger.isHost = true;
			messenger.port = port;
			messengerThread = new Thread(messenger, "Secure Messenger Server");
			messengerThread.start();
			
		}
		else if(e.getSource() == sendButton)
		{
			OutputPrintln("You:\n" + inputBox.getText());
			messenger.Send(inputBox.getText());
			inputBox.setText("");
		}
	}
	public void isSending(boolean b)
	{
        SwingUtilities.invokeLater(new Runnable() {
            public void run() {
            	sendButton.setEnabled(b);
            	inputBox.setEnabled(b);
            }
        });
	}
	/**
	 * Prints to the output box on the frame.
	 * @param str
	 */
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
