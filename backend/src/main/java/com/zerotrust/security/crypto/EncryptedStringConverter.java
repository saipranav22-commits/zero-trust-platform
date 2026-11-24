package com.zerotrust.security.crypto;

import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

/**
 * JPA Attribute Converter for Field-Level AES-256-GCM Encryption.
 * Transparently encrypts sensitive entity attributes on write and decrypts on read.
 * Backwards compatible with legacy unencrypted data during migration.
 */
@Converter
@Component
public class EncryptedStringConverter implements AttributeConverter<String, String> {

    private static volatile AesGcmEncryptionService serviceDelegate;

    @Autowired
    public void setAesGcmEncryptionService(AesGcmEncryptionService service) {
        EncryptedStringConverter.serviceDelegate = service;
    }

    public static void setDelegate(AesGcmEncryptionService service) {
        EncryptedStringConverter.serviceDelegate = service;
    }

    @Override
    public String convertToDatabaseColumn(String attribute) {
        if (attribute == null) {
            return null;
        }
        if (serviceDelegate == null) {
            return attribute;
        }
        if (serviceDelegate.isEncrypted(attribute)) {
            return attribute;
        }
        return serviceDelegate.encrypt(attribute);
    }

    @Override
    public String convertToEntityAttribute(String dbData) {
        if (dbData == null) {
            return null;
        }
        if (serviceDelegate == null) {
            return dbData;
        }
        return serviceDelegate.decrypt(dbData);
    }
}
