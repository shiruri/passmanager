package com.passwordmanager;

import org.apache.commons.cli.*;
import java.util.Properties;
import java.util.Random;
import javax.mail.*;
import javax.mail.internet.*;
import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.Base64;
import java.util.HashMap;
import java.util.Scanner;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import com.itextpdf.text.DocumentException;

import java.io.File;
import java.security.Security;
import java.text.ParseException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import javax.mail.MessagingException;

public class Main {
    public static void main(String[] args) throws org.apache.commons.cli.ParseException, ParseException, MessagingException {
        Logger logger = LoggerFactory.getLogger(passwordAdd.class); // SLF4J Logger instance

        HashMap<Integer, String> userAccount = new HashMap<>();
        int currentId = 1; // Start IDs from 1
        Scanner scan = new Scanner(System.in); // Single Scanner instance

        // Define command-line options
        Options options = new Options();
        options.addOption("h", "help", false, "Display help");
        options.addOption("al", "AccList", false, "Display Account list(s)");
        options.addOption("cr", "create", true, "Create a new account");
        options.addOption("v", "version", false, "Show application version");
        options.addOption("log", "log", false, "Log in to Existing Account");
        options.addOption("pw", "Pw", true, "Add a password (format: --Pw Add <website> <password>)");

        // Parse the command-line arguments
        CommandLineParser parser = new DefaultParser();
        CommandLine cmd;
        cmd = parser.parse(options, args);

        // Handle command-line options
        if (cmd.hasOption("h")) {
            displayHelp(options);
            return;
        }
        if (cmd.hasOption("v")) {
            System.out.println("Password Manager Version 1.0");
            return;
        }
        if (cmd.hasOption("al")) {
            System.out.println(userAccount);
            return;
        }
        if (cmd.hasOption("cr")) {
            String accountName = cmd.getOptionValue("cr");
            System.out.println("Creating account for: " + accountName);
            passwordAdd pass = new passwordAdd(userAccount, currentId);
            pass.setPassword(scan);
            userAccount.put(currentId++, accountName); // Store account
            return;
        }

        // Handle password addition through command-line
        if (cmd.hasOption("pw")) {
            String[] values = cmd.getOptionValues("pw");
            if (values.length == 3 && values[0].equalsIgnoreCase("Add")) {
                String website = values[1];
                String password = values[2];

                // Create an instance of passwordAdd
                passwordAdd newPassword = new passwordAdd(website, password);

                try {
                    // Add the password to the PDF
                    newPassword.passwordadd(scan); // Implement the logic to add and encrypt the password
                } catch (FileNotFoundException | DocumentException e) {
                    e.printStackTrace();
                }
                return;
            }
        }

    
        boolean isNotLoggedIn = true;

        // Main interface loop
        while (isNotLoggedIn) {
            System.out.println("######################################");
            System.out.println("#          PASSWORD MANAGER          #");
            System.out.println("#                                    #");
            System.out.println("#        cr to create an account     #");
            System.out.println("#           log to login             #");
            System.out.println("######################################");

            // Get the command from user input
            String command = scan.nextLine().trim();

            // Handle account creation
            if (command.equalsIgnoreCase("cr")) {
                System.out.println("Creating a new account...");
                passwordAdd cr = new passwordAdd(userAccount, currentId);
                cr.setPassword(scan); // Correct method call
                currentId++;
            }

            // Handle login
            else if (command.equalsIgnoreCase("log")) {
                System.out.print("Enter your account name: ");
                String accountName = scan.nextLine().trim();

                // Attempt to log in
                try {
                    // Call the login method to handle login logic
                	passwordAdd manager = new passwordAdd();
                    manager.login(scan);

                    // If login is successful, break out of the loop
                    isNotLoggedIn = false;

                } catch (Exception e) {
                    System.out.println("An error occurred during login: " + e.getMessage());
                    logger.error("Login error: {}", e.getMessage());
                }
            }

            // Handle invalid command
            else {
                System.out.println("Invalid command. Please enter 'cr' to create an account or 'log' to login.");
            }
        }

        // Continue with application after login
        System.out.println("Welcome to your Password Manager!");
        // Add additional functionality here if needed
   
        // Once logged in, show the main menu
        System.out.println("######################################"); 
        System.out.println("#          PASSWORD MANAGER          #");
        System.out.println("#           -h for help              #");
        System.out.println("######################################");
        Scanner scan1 = new Scanner(System.in);
        while (true) {
            System.out.println("Enter a command:");
            String command = scan1.nextLine();

            if (command.equalsIgnoreCase("--Pw Add")) {
                System.out.print("Enter the website: ");
                String website = scan1.nextLine();
                System.out.print("Enter the password: ");
                String password = scan1.nextLine();

                // Create an instance of passwordAdd
                passwordAdd newPassword = new passwordAdd(website, password);
                try {
                    newPassword.passwordadd(scan1);
                } catch (FileNotFoundException | DocumentException e) {
                    e.printStackTrace();
                }
            } else if (command.equalsIgnoreCase("-h") || command.equalsIgnoreCase("--help")) {
                displayHelp(options);
            } else if (command.equalsIgnoreCase("-eml") || command.equalsIgnoreCase("--email")) {
                passwordAdd emaillink = new passwordAdd();
                try {
                    emaillink.emailLink();
                } catch (MessagingException e) {
                    e.printStackTrace();
                }
            } else if (command.equalsIgnoreCase("-pr") || command.equalsIgnoreCase("--passr")) {
                passwordAdd passres = new passwordAdd();
                System.out.println("Password reset");
                passres.Resetpass();
            } else if (command.equalsIgnoreCase("-al") || command.equalsIgnoreCase("--acc")) {
                System.out.println("List of accounts");
                System.out.println(userAccount);
            } else if (command.equalsIgnoreCase("-v") || command.equalsIgnoreCase("--version")) {
                System.out.println("Password Manager Version 1.0");
            } else if (command.equalsIgnoreCase("-Pw acc") || command.equalsIgnoreCase("--accountview")) {
                passwordAdd vw = new passwordAdd();
                // Check password before viewing credentials
                if (vw.passwordcheck()) {
                    vw.viewCredentials(); // View credentials if password check is successful
                } else {
                    System.out.println("Access to view credentials denied due to incorrect password.");
                }
            } else if (command.equalsIgnoreCase("-Pw vw")) {
                passwordAdd vw = new passwordAdd();
                if (vw.passwordcheck()) {
                    vw.viewPasswordsPdf(); // View credentials if password check is successful
                } else {
                    System.out.println("Access to view credentials denied due to incorrect password.");
                }
            } else if (command.equalsIgnoreCase("-Pw rem") || command.equalsIgnoreCase("--passrem")) {
                System.out.println("Deleting Password");
                // Use forward slashes for cross-platform compatibility
                String filepath = "passmanager/src/main/java/com/userpassword/passwords.pdf";
                System.out.println("Note: This will delete all the passwords.");
                logger.warn("The following will be deleted: {}", filepath);

                System.out.println("Continue? (Y/N)");
                String userInput = scan1.nextLine();
                if (userInput.equalsIgnoreCase("Y")) {
                    File fileToDelete = new File(filepath);
                    logger.info("Attempting to delete file at absolute path: {}", fileToDelete.getAbsolutePath());

                    if (fileToDelete.exists()) {
                        passwordAdd rem = new passwordAdd();
                        boolean isDeleted = rem.deleteFile(filepath);
                        if (isDeleted) {
                            logger.info("File {} deleted successfully.", filepath);
                            System.out.println("File deleted successfully.");
                        } else {
                            logger.error("Failed to delete the file: {}", filepath);
                            System.out.println("Failed to delete the file. Please check if the file is open or in use.");
                        }
                    } else {
                        logger.warn("File does not exist at: {}", fileToDelete.getAbsolutePath());
                        System.out.println("The file does not exist.");
                    }
                } else {
                    logger.info("Deletion aborted by the user.");
                    System.out.println("Exiting");
                }
            }
        }
    }

    private static void displayHelp(Options options) {
        HelpFormatter formatter = new HelpFormatter();
        String header = "Password Manager - A tool to manage passwords securely.\n\n";
        String footer = "\nFor more information, visit the project repository.";

        // Printing the custom commands
        String commands = "\nCustom Commands:\n" +
                "  -h   Display help\n" +
                "  -v   Show application version\n" +
                "  -al  Show Account Lists\n" +
                "  --cr Add a new Account\n" +
                "  --eml Add Email\n" +
                "  --pr Reset Password\n" +
                "  --Pw Add   Add a password\n" +
                "  --Pw Rem   Remove a password\n" +
                "  --Pw vw  To view a password\n";

        // Print the help with custom commands
        formatter.printHelp("PasswordManager", header, options, footer, true);
        System.out.println(commands); // Print custom command list
    }
}
