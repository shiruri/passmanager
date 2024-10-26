package com.passwordmanager;

import org.apache.commons.cli.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.itextpdf.text.Document;
import com.itextpdf.text.DocumentException;
import com.itextpdf.text.*;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.PdfWriter;
import com.itextpdf.text.pdf.parser.LocationTextExtractionStrategy;
import com.itextpdf.text.pdf.parser.PdfReaderContentParser;
import com.itextpdf.text.pdf.parser.PdfTextExtractor;
import com.itextpdf.text.pdf.parser.SimpleTextExtractionStrategy;

import javax.mail.*;
import javax.mail.internet.*;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;


import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.parser.PdfTextExtractor;
import java.io.IOException;

import java.io.*;
import java.util.Base64;
import java.util.HashMap;
import java.util.Properties;
import java.util.Random;
import java.util.Scanner;
import java.security.Security;


 class passwordAdd {
    private static final Logger logger = LoggerFactory.getLogger(passwordAdd.class); // SLF4J Logger instance
    private String website;
    private String userPassword;
    private String username;
    private String email;
    HashMap<Integer, String> userAccount; // Store userAccount
    private int currentId;

    static final String ALGORITHM = "AES";
    private static final String IV = "RandomInitVector"; // 16 characters long

    static final String FILE_PATH = "src/main/java/com/userpassword/userpassword.txt";
    static final String KEY_FILE_PATH = "src/main/java/com/aesKey.key";

    // Constructor with userAccount and currentId
    public passwordAdd(HashMap<Integer, String> userAccount, int currentId) {
        this.userAccount = userAccount != null ? userAccount : new HashMap<>();
        this.currentId = currentId;
    }

    public passwordAdd(String website, String password) {
        this.website = website;
        this.userPassword = password;
    }

    public passwordAdd() {
    }

    boolean isNotloggedin = true;
    boolean invalid = true;

    public void PasswordManager(HashMap<Integer, String> userAccount) {
        this.userAccount = userAccount != null ? userAccount : new HashMap<>();
        this.currentId = userAccount.size(); // Initialize currentId based on existing accounts
    }

    public static SecretKey getKey() throws Exception {
        byte[] keyBytes = new byte[16]; // Ensure this matches the key size
        try (FileInputStream keyInput = new FileInputStream(KEY_FILE_PATH)) {
            keyInput.read(keyBytes);
        }
        return new SecretKeySpec(keyBytes, ALGORITHM);
    }


    public void setPassword(Scanner scan) {
        logger.info("Enter Username:");
        username = scan.nextLine().trim(); // Get and trim username input
        logger.info("######################################");
        logger.info("#   Enter a password (8-20 chars)    #");
        logger.info("#  It can include letters and digits #");
        logger.info("######################################");

        while (true) {
            String inputPassword = scan.nextLine().trim(); // Get and trim password input
            if (isPasswordValid(inputPassword)) {
                userPassword = inputPassword;
                logger.info("Password is valid");

                logger.info("Link Email? (Y/N)");
                String linkEmail = scan.nextLine().trim();
                if (linkEmail.equalsIgnoreCase("Y")) {
                    logger.info("Enter email to be linked:");
                    email = scan.nextLine().trim(); // Get and trim email input
                } else {
                    logger.info("Email linking skipped.");
                    email = null;  // No email linked
                }

                saveUserCredentials(); // Save credentials after all validations
                userAccount.put(currentId++, username); // Store account in userAccount with incremented ID
                logger.info("UserAccount updated: {}", userAccount);
                break; // Exit the loop once the password is set and saved
            } else {
                logger.warn("Password is invalid. Ensure it has 8-20 characters and includes at least one digit.");
            }
        }
    }

    private boolean isPasswordValid(String password) {
        return password.length() >= 8 && password.length() <= 20 && password.matches(".*\\d.*");
    }

    public void saveUserCredentials() {
        try {
            SecretKey key = getKey(); // Retrieve the existing key
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            IvParameterSpec ivParams = new IvParameterSpec(IV.getBytes()); // Use the same IV
            cipher.init(Cipher.ENCRYPT_MODE, key, ivParams);

            // Encrypt password
            byte[] encryptedPassword = cipher.doFinal(userPassword.getBytes());
            String encodedPassword = Base64.getEncoder().encodeToString(encryptedPassword);

            // Encrypt the email if it exists
            String encodedEmail = null;
            if (email != null) {
                cipher.init(Cipher.ENCRYPT_MODE, key, ivParams); // Reinitialize the cipher for email encryption
                byte[] encryptedEmail = cipher.doFinal(email.getBytes());
                encodedEmail = Base64.getEncoder().encodeToString(encryptedEmail);
            }

            // Write username, email, and encrypted password to the file
            try (PrintWriter pr = new PrintWriter(new FileWriter(FILE_PATH, true))) {
                // Check if the file is empty to avoid redundant newlines
                if (new File(FILE_PATH).length() == 0) {
                    pr.println(username + "," + (encodedEmail != null ? encodedEmail : "") + "," + encodedPassword);
                } else {
                    pr.println(username + "," + (encodedEmail != null ? encodedEmail : "") + "," + encodedPassword);
                }
            }

            logger.info("Username, email, and encrypted password saved to file.");
        } catch (Exception e) {
            logger.error("An error occurred while saving user credentials.", e);
        }
    }


    public String readAndDecryptEmail() {
        try {
            SecretKey key = getKey(); // Retrieve the existing key
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            IvParameterSpec ivParams = new IvParameterSpec(IV.getBytes()); // Use the same IV

            try (BufferedReader br = new BufferedReader(new FileReader(FILE_PATH))) {
                String line = br.readLine();
                if (line != null) {
                    String[] userDetails = line.split(",");
                    if (userDetails.length < 2) {
                        System.out.println("Error: Incomplete user details in file.");
                        return null;
                    }

                    String encryptedEmail = userDetails[1];
                    byte[] decodedEmail = Base64.getDecoder().decode(encryptedEmail);

                    cipher.init(Cipher.DECRYPT_MODE, key, ivParams); // Initialize cipher for decryption
                    byte[] decryptedEmail = cipher.doFinal(decodedEmail);

                    return new String(decryptedEmail);
                } else {
                    System.out.println("No email found in the file.");
                }
            }
        } catch (Exception e) {
            System.out.println("An error occurred while decrypting the email.");
            e.printStackTrace();
        }
        return null;
    }
    public String readAndDecryptPassword() {
        SecretKey key;
        Cipher cipher;
        IvParameterSpec ivParams;
        String encryptedFilePath = "passmanager/src/main/java/com/userpassword/userpassword.txt"; // Update the path as needed

        try {
            key = getKey(); // Retrieve the existing key
            cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            ivParams = new IvParameterSpec(IV.getBytes()); // Use the same IV

            logger.info("Attempting to read from file: {}", encryptedFilePath);
            try (BufferedReader br = new BufferedReader(new FileReader(encryptedFilePath))) {
                String line = br.readLine();
                if (line == null || line.trim().isEmpty()) {
                    logger.warn("No password found in the file.");
                    return null; // Return null if no data is found
                }

                String[] userDetails = line.split(",");
                if (userDetails.length < 3) {
                    logger.error("Incomplete user details in file: {}", line);
                    throw new IllegalStateException("Incomplete user details in file.");
                }

                String encryptedPassword = userDetails[2];
                byte[] decodedPassword = Base64.getDecoder().decode(encryptedPassword);

                // Initialize cipher for decryption
                cipher.init(Cipher.DECRYPT_MODE, key, ivParams);
                byte[] decryptedPassword = cipher.doFinal(decodedPassword);

                logger.info("Password decrypted successfully.");
                return new String(decryptedPassword);
            }
        } catch (FileNotFoundException e) {
            logger.error("Encrypted password file not found: {}", e.getMessage());
        } catch (IOException e) {
            logger.error("An error occurred while reading the password file: {}", e.getMessage());
        } catch (IllegalStateException e) {
            logger.error("Error: {}", e.getMessage());
        } catch (Exception e) {
            logger.error("An error occurred while decrypting the password: {}", e.getMessage());
        }

        return null; // Return null if decryption fails for any reason
    }
    private String decryptPassword(String encryptedPassword) {
        try {
            SecretKey key = getKey(); // Retrieve the existing key
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            IvParameterSpec ivParams = new IvParameterSpec(IV.getBytes()); // Use the same IV
            byte[] decodedPassword = Base64.getDecoder().decode(encryptedPassword);

            cipher.init(Cipher.DECRYPT_MODE, key, ivParams); // Initialize cipher for decryption
            byte[] decryptedPassword = cipher.doFinal(decodedPassword);
            return new String(decryptedPassword);
        } catch (Exception e) {
            logger.error("An error occurred while decrypting the password: {}", e.getMessage());
            return null; // Return null if decryption fails
        }
    }
    private String[] readUserCredentials(String accountName) throws IOException {
        try (BufferedReader br = new BufferedReader(new FileReader(FILE_PATH))) {
            String line;
            while ((line = br.readLine()) != null) {
                String[] userDetails = line.split(",");
                if (userDetails[0].equalsIgnoreCase(accountName)) {
                    return userDetails; // Return the user details if the account name matches
                }
            }
        }
        return null; // Return null if no account found
    }
 // Attempt to read credentials from the file
    public void login(Scanner scan) {
        System.out.println("Logging in...");
        System.out.print("Enter your account name: ");
        String accountName = scan.nextLine().trim();
    try {
        String[] userDetails = readUserCredentials(accountName);
        if (userDetails == null) {
            System.out.println("No account found with that name. Please create an account first.");
            return;
        }

        String encryptedPassword = userDetails[2]; // Assuming the password is the third element
        String decryptedPassword = decryptPassword(encryptedPassword);

        if (decryptedPassword == null) {
            System.out.println("Failed to decrypt password. Please check your credentials.");
            return;
        }

        System.out.println("Input Password:");
        String inputPassword = scan.nextLine();

        if (inputPassword.equals(decryptedPassword)) {
            System.out.println("Login successful!");
            // Proceed with post-login actions
        } else {
            System.out.println("Incorrect password. Please try again.");
        }
    } catch (Exception e) {
        System.out.println("An error occurred during login: " + e.getMessage());
        logger.error("Login error: {}", e.getMessage());
    }
}
    private String decryptPassword1(String encryptedPassword) {
        try {
            SecretKey key = getKey(); // Retrieve the existing key
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            IvParameterSpec ivParams = new IvParameterSpec(IV.getBytes()); // Use the same IV
            byte[] decodedPassword = Base64.getDecoder().decode(encryptedPassword);

            cipher.init(Cipher.DECRYPT_MODE, key, ivParams); // Initialize cipher for decryption
            byte[] decryptedPassword = cipher.doFinal(decodedPassword);
            return new String(decryptedPassword);
        } catch (Exception e) {
            logger.error("An error occurred while decrypting the password: {}", e.getMessage());
            return null; // Return null if decryption fails
        }
    }
 

    // Method to add password to the PDF
    public void passwordadd(Scanner scan) throws FileNotFoundException, DocumentException {
        String inputPassword;
        String decryptedPassword = readAndDecryptPassword(); // Get decrypted password
        logger.info("Decrypted password: {}", decryptedPassword); // Log the decrypted password for debugging
        boolean invalidpass = false;
        int Passwordtries = 5;

        while (!invalidpass && Passwordtries > 0) {
            logger.info("Enter Password:");
            inputPassword = scan.nextLine().trim(); // Trim whitespace

            if (inputPassword.equals(decryptedPassword)) {
                Document document = new Document();
                PdfWriter.getInstance(document, new FileOutputStream("src/main/java/com/passwords.pdf"));
                document.open();
                document.add(new Paragraph("Website: " + website + "\nUsername: " + username + "\nPassword: " + userPassword));
                document.close();
                logger.info("Password added successfully to the PDF.");

                // Encrypt and save PDF
                encryptFile("src/main/java/com/passwords.pdf", "src/main/java/com/encrypted_passwords.pdf", decryptedPassword);

                // Encrypt and save user credentials
                encryptFile(FILE_PATH, "src/main/java/com/encrypted_userpassword.txt", decryptedPassword);

                // Delete original files after encryption for security
                deleteFile("src/main/java/com/passwords.pdf");
                deleteFile(FILE_PATH);

                invalidpass = true; // Exit the loop on success
            } else {
                logger.warn("Incorrect password. Access denied.");
                Passwordtries--;

                if (Passwordtries <= 0) {
                    logger.warn("Too many incorrect attempts. Exiting.");
                }
            }
        }
    }


    // Encrypt a file using AES
    public static void encryptFile(String inputFilePath, String outputFilePath, String password) {
        try {
            // Generate key
            KeyGenerator keyGen = KeyGenerator.getInstance(ALGORITHM);
            keyGen.init(128); // AES key size
            SecretKey secretKey = keyGen.generateKey();

            // Create cipher
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);

            // Read input file
            byte[] inputBytes = java.nio.file.Files.readAllBytes(new File(inputFilePath).toPath());
            byte[] outputBytes = cipher.doFinal(inputBytes);

            // Write output file
            try (FileOutputStream outputStream = new FileOutputStream(outputFilePath)) {
                outputStream.write(outputBytes);
            }

            logger.info("File encrypted successfully.");
        } catch (Exception e) {
            logger.error("An error occurred during file encryption.", e);
        }
    }

    // Method to delete a file
    public boolean deleteFile(String filePath) {
        File file = new File(filePath);
        logger.info("Attempting to delete file at absolute path: {}", file.getAbsolutePath());

        if (file.exists()) {
            boolean isDeleted = file.delete();
            if (isDeleted) {
                logger.info("Deleted the file: {}", filePath);
            } else {
                logger.error("Failed to delete the file: {}", filePath);
                System.out.println("Failed to delete the file. Please check if it is in use or if permissions are correct.");
            }
            return isDeleted;
        } else {
            logger.warn("File {} does not exist.", file.getAbsolutePath());
            System.out.println("The file does not exist.");
            return false;
        }
    }


    public void emailLink() throws MessagingException {
        // First, attempt to read and decrypt the email
        String decryptedEmail = readAndDecryptEmail();

        // Check if the decrypted email is null
        if (decryptedEmail == null || decryptedEmail.isEmpty()) {
            System.out.println("No email linked or decryption failed. Please enter your email address:");
            try (Scanner scan = new Scanner(System.in)) { // Use try-with-resources to ensure Scanner is closed
                decryptedEmail = scan.nextLine(); // Prompt the user to enter their email

                // Validate the email format
                if (!isValidEmail(decryptedEmail)) {
                    System.out.println("Invalid email format. Please enter a valid email address.");
                    return; // Exit the method if the email format is invalid
                }
            }
        } else {
            System.out.println("Linked email: " + decryptedEmail); // Display the linked email
        }

        // Email properties setup
        final String username = System.getenv("EMAIL_USERNAME"); // Use environment variables
        final String password = System.getenv("EMAIL_PASSWORD"); // Use environment variables

        Properties prop = new Properties();
        prop.put("mail.smtp.auth", "true");
        prop.put("mail.smtp.starttls.enable", "true");
        prop.put("mail.smtp.host", "smtp.gmail.com");
        prop.put("mail.smtp.port", "587");

        // Create session with authentication
        Session session = Session.getInstance(prop, new javax.mail.Authenticator() {
            protected PasswordAuthentication getPasswordAuthentication() {
                return new PasswordAuthentication(username, password);
            }
        });

        try {
            // Construct and send email
            Message message = new MimeMessage(session);
            message.setFrom(new InternetAddress(username)); // Set the sender's email
            message.setRecipients(Message.RecipientType.TO, InternetAddress.parse(decryptedEmail));
            message.setSubject("Account Created in Password Manager");
            message.setText("Hello " + this.username + ",\n\nYour account has been successfully created.");

            Transport.send(message);
            System.out.println("Confirmation email sent successfully!");
        } catch (MessagingException e) {
            System.err.println("Failed to send email: " + e.getMessage());
            throw e; // Rethrow exception for higher-level handling if necessary
        }
    }

    // Method to validate email format
    private boolean isValidEmail(String email) {
        String emailRegex = "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,6}$";
        return email.matches(emailRegex);
    }

    public void Resetpass() {
        try {
            Scanner scan = new Scanner(System.in);
            Random rand = new Random();
            int resetCode = 1000 + rand.nextInt(9000);

            // Attempt to read and decrypt the email
            String decryptedEmail = readAndDecryptEmail();

            // Check if the decrypted email is null
            if (decryptedEmail == null || decryptedEmail.isEmpty()) {
                System.out.println("No email linked or decryption failed. Please enter your email address for password reset:");
                email = scan.nextLine(); // Set the email variable if decryption fails
            } else {
                email = decryptedEmail; // Use the decrypted email
                System.out.println("Linked email: " + email); // Display the linked email
            }

            // Email properties setup
            Properties prop = new Properties();
            prop.put("mail.smtp.auth", "true");
            prop.put("mail.smtp.starttls.enable", "true");
            prop.put("mail.smtp.host", "smtp.gmail.com");
            prop.put("mail.smtp.port", "587");

            Session session = Session.getInstance(prop, new javax.mail.Authenticator() {
                protected PasswordAuthentication getPasswordAuthentication() {
                    return new PasswordAuthentication("p98846575@gmail.com", "yykr lksv ohfr avpy");
                }
            });

            // Construct and send email
            Message message = new MimeMessage(session);
            message.setFrom(new InternetAddress("p98846575@gmail.com"));
            message.setRecipients(Message.RecipientType.TO, InternetAddress.parse(email));
            message.setSubject("Password Manager Password Reset");
            message.setText("Hello " + this.username + ",\n\nYour password reset code is: " + resetCode);

            Transport.send(message);
            System.out.println("Reset code sent to your email.");

            // Prompt user to enter the reset code ffs how to fix this
            System.out.println("Enter the reset code:");
            int userCode = scan.nextInt();

            if (userCode == resetCode) {
                System.out.println("Reset code verified. You may now set a new password.");
                resetpasswordandusername();
            } else {
                System.out.println("Incorrect reset code. Password reset failed.");
            }

        } catch (MessagingException e) {
            System.out.println("Failed to send reset email.");
            e.printStackTrace();
        }
    }

    public void resetpasswordandusername() {
        Scanner scan = new Scanner(System.in);
        boolean isValid = false; // Corrected: Set to false initially Cuz freak me

        // Input for username
        System.out.println("Enter Username:");
        this.username = scan.nextLine();

        // Input for password with validation
        System.out.println("######################################");
        System.out.println("#   Enter a password (8-20 chars)    #");
        System.out.println("#  It can include letters and digits #");
        System.out.println("######################################");

        while (!isValid) { // Loop until a valid password is entered
            String inputPassword = scan.nextLine();

            // Validate password length and digit presence
            if (inputPassword.length() >= 8 && inputPassword.length() <= 20 && inputPassword.matches(".*\\d.*")) {
                isValid = true;
                userPassword = inputPassword;
                System.out.println("Password is valid");
                System.out.println("Password Reset succesfull");
            } else {
                System.out.println("Password is invalid. Ensure it has 8-20 characters and includes at least one digit.");
            }
        }
    }
    public void viewCredentials() {
        try {
            // Retrieve encryption key and cipher setup
            SecretKey key = getKey(); // Retrieve the AES key from the key file
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            IvParameterSpec ivParams = new IvParameterSpec(IV.getBytes()); // IV for AES encryption

            // Open the file with stored credentials
            try (BufferedReader br = new BufferedReader(new FileReader(FILE_PATH))) {
                String line;
                while ((line = br.readLine()) != null) {
                    // Split line into components (username, email, password)
                    String[] userDetails = line.split(",");
                    if (userDetails.length < 3) {
                        System.out.println("Error: Incomplete user details in file.");
                        continue; // Skip incomplete records
                    }

                    String username = userDetails[0];
                    String encryptedEmail = userDetails[1];
                    String encryptedPassword = userDetails[2];

                    // Decrypt email
                    byte[] decodedEmail = Base64.getDecoder().decode(encryptedEmail);
                    cipher.init(Cipher.DECRYPT_MODE, key, ivParams);
                    String decryptedEmail = new String(cipher.doFinal(decodedEmail));

                    // Decrypt password
                    byte[] decodedPassword = Base64.getDecoder().decode(encryptedPassword);
                    String decryptedPassword = new String(cipher.doFinal(decodedPassword));

                    // Display decrypted credentials
                    System.out.println("Username: " + username);
                    System.out.println("Email: " + decryptedEmail);
                    System.out.println("Password: " + decryptedPassword);
                    System.out.println("=======================================");
                }
            }
        } catch (Exception e) {
            System.out.println("An error occurred while viewing credentials.");
            e.printStackTrace();
        }
    }
    public boolean passwordcheck() {
        Scanner scan = new Scanner(System.in);

        // Read and decrypt the stored password
        String decryptedPassword = readAndDecryptPassword();

        if (decryptedPassword == null) {
            System.out.println("No password found or decryption failed.");
            return false;
        }

        // Prompt the user to input a password for verification
        System.out.println("Input password:");
        String passcheck = scan.nextLine();

        // Check if the input password matches the stored password
        if (passcheck.equals(decryptedPassword)) {
            System.out.println("Password match successful!");
            return true;
        } else {
            System.out.println("Incorrect password. Access denied.");
            return false;
        }
    }
  
  


  
    public void viewPasswordsPdf() {
        // Updated path to the encrypted PDF file
        String pdfPath = "src/main/java/com/encrypted_passwords.pdf"; 
        String decryptionPassword = readAndDecryptPassword(); // Retrieve the decryption password

        if (decryptionPassword == null || decryptionPassword.isEmpty()) {
            System.out.println("Failed to retrieve the decryption password.");
            return;
        }

        // Using try-with-resources to ensure PdfReader is closed automatically
        try {
            PdfReader reader = new PdfReader(pdfPath, decryptionPassword.getBytes()); // Open the encrypted PDF with the decryption password
            PdfReaderContentParser parser = new PdfReaderContentParser(reader); // Parser for content extraction
            int pageCount = reader.getNumberOfPages(); // Get the total number of pages

            for (int i = 1; i <= pageCount; i++) {
                // Extract text from each page using LocationTextExtractionStrategy
                String pageContent = parser.processContent(i, new LocationTextExtractionStrategy()).getResultantText();
                System.out.println("Page " + i + " Content: \n" + pageContent); // Print the extracted content
                System.out.println("=======================================");
            }
        } catch (IOException e) {
            System.out.println("An error occurred while reading the PDF. Check the file path and password.");
            e.printStackTrace(); // Print stack trace for debugging
        } catch (Exception e) {
            System.out.println("An unexpected error occurred.");
            e.printStackTrace(); // Print stack trace for unexpected exceptions
        }
    }


}

