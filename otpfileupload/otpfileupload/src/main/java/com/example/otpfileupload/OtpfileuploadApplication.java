package com.example.otpfileupload;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeMessage;
import jakarta.servlet.http.HttpSession;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.http.ResponseEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;

import java.io.*;
import java.nio.file.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.util.*;
import java.util.stream.Collectors;

@SpringBootApplication
@RestController
@RequestMapping("/api")
public class OtpfileuploadApplication {

    public static void main(String[] args) {
        SpringApplication.run(OtpfileuploadApplication.class, args);
    }

    @Autowired
    private JavaMailSender mailSender;

    private final Map<String, String> otpStorage = new HashMap<>();

    // Secret key for encryption/decryption (use secure management in production)
    private static final String SECRET_KEY = "1234567890123456"; // 16 bytes key for AES

    @PostMapping("/send-otp")
    public String sendOTP(@RequestBody Map<String, String> request) {
        String email = request.get("email");
        if (email == null || email.isEmpty()) {
            return "Invalid email address";
        }

        String otp = String.valueOf(new Random().nextInt(900000) + 100000);
        otpStorage.put(email, otp);

        try {
            sendEmail(email, "Your OTP Code", "Welcome to Secure file storage system,\n" +
                    "Your OTP is: " + otp);
            return "OTP sent successfully!";
        } catch (MessagingException e) {
            e.printStackTrace();
            return "Failed to send OTP";
        }
    }

    @PostMapping("/verify-otp")
    public String verifyOTP(@RequestBody Map<String, String> request, HttpSession session) {
        String email = request.get("email");
        String otp = request.get("otp");

        if (email == null || otp == null || !otp.equals(otpStorage.get(email))) {
            return "Invalid OTP";
        }

        otpStorage.remove(email);
        session.setAttribute("authenticated", true);
        session.setAttribute("email", email);
        return "OTP verified successfully! Logged in.";
    }

    @PostMapping("/upload")
    public String uploadFile(@RequestParam("file") MultipartFile file, HttpSession session) {
        Boolean isAuthenticated = (Boolean) session.getAttribute("authenticated");
        String email = (String) session.getAttribute("email");

        if (isAuthenticated == null || !isAuthenticated || email == null) {
            return "Unauthorized: Please verify OTP to login first.";
        }

        if (file.isEmpty()) {
            return "Please select a file to upload";
        }

        try {
            Path userDir = Paths.get("uploads", email);
            Files.createDirectories(userDir);
            Path filePath = userDir.resolve(file.getOriginalFilename());

            // Encrypt and save
            encryptFile(file.getInputStream(), filePath);

            return "File uploaded and encrypted successfully: " + file.getOriginalFilename();
        } catch (Exception e) {
            e.printStackTrace();
            return "File upload failed";
        }
    }

    @GetMapping("/files")
    public ResponseEntity<List<String>> listUploadedFiles(HttpSession session) {
        Boolean isAuthenticated = (Boolean) session.getAttribute("authenticated");
        String email = (String) session.getAttribute("email");

        if (isAuthenticated == null || !isAuthenticated || email == null) {
            return ResponseEntity.status(401).body(List.of("Unauthorized: Please login first."));
        }

        try {
            Path userDir = Paths.get("uploads", email);
            if (!Files.exists(userDir)) {
                return ResponseEntity.ok(Collections.emptyList());
            }

            List<String> fileNames = Files.list(userDir)
                    .map(path -> email + "/" + path.getFileName().toString())
                    .collect(Collectors.toList());

            return ResponseEntity.ok(fileNames);
        } catch (IOException e) {
            e.printStackTrace();
            return ResponseEntity.status(500).body(List.of("Error reading file list."));
        }
    }

    @GetMapping("/download/{email}/{filename}")
    public ResponseEntity<byte[]> downloadFile(@PathVariable String email,
                                               @PathVariable String filename,
                                               HttpSession session) {
        Boolean isAuthenticated = (Boolean) session.getAttribute("authenticated");
        String sessionEmail = (String) session.getAttribute("email");

        if (isAuthenticated == null || !isAuthenticated || !email.equals(sessionEmail)) {
            return ResponseEntity.status(401).build();
        }

        try {
            Path filePath = Paths.get("uploads", email, filename);
            if (!Files.exists(filePath)) {
                return ResponseEntity.notFound().build();
            }

            // Decrypt and send
            byte[] decryptedData = decryptFile(filePath);

            return ResponseEntity.ok()
                    .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + filename + "\"")
                    .contentType(MediaType.APPLICATION_OCTET_STREAM)
                    .body(decryptedData);
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(500).build();
        }
    }

    @DeleteMapping("/files/{email}/{filename}")
    public ResponseEntity<String> deleteFile(@PathVariable String email,
                                             @PathVariable String filename,
                                             HttpSession session) {
        Boolean isAuthenticated = (Boolean) session.getAttribute("authenticated");
        String sessionEmail = (String) session.getAttribute("email");

        if (isAuthenticated == null || !isAuthenticated || !email.equals(sessionEmail)) {
            return ResponseEntity.status(401).body("Unauthorized");
        }

        try {
            Path filePath = Paths.get("uploads", email, filename);
            if (Files.exists(filePath)) {
                Files.delete(filePath);
                return ResponseEntity.ok("File deleted successfully.");
            } else {
                return ResponseEntity.status(404).body("File not found.");
            }
        } catch (IOException e) {
            e.printStackTrace();
            return ResponseEntity.status(500).body("Error deleting file.");
        }
    }

    @PostMapping("/logout")
    public String logout(HttpSession session) {
        session.invalidate();
        return "Logged out successfully!";
    }

    private void sendEmail(String to, String subject, String text) throws MessagingException {
        MimeMessage message = mailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(message, true);
        helper.setTo(to);
        helper.setSubject(subject);
        helper.setText(text);
        helper.setFrom(new InternetAddress("abi.blockchaindev@gmail.com"));
        mailSender.send(message);
    }

    private void encryptFile(InputStream inputStream, Path outputPath) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        SecretKeySpec keySpec = new SecretKeySpec(SECRET_KEY.getBytes(), "AES");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);

        try (CipherOutputStream cipherOut = new CipherOutputStream(Files.newOutputStream(outputPath), cipher)) {
            byte[] buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = inputStream.read(buffer)) != -1) {
                cipherOut.write(buffer, 0, bytesRead);
            }
        }
    }

    private byte[] decryptFile(Path inputPath) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        SecretKeySpec keySpec = new SecretKeySpec(SECRET_KEY.getBytes(), "AES");
        cipher.init(Cipher.DECRYPT_MODE, keySpec);

        try (CipherInputStream cipherIn = new CipherInputStream(Files.newInputStream(inputPath), cipher);
             ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = cipherIn.read(buffer)) != -1) {
                out.write(buffer, 0, bytesRead);
            }
            return out.toByteArray();
        }
    }
}
