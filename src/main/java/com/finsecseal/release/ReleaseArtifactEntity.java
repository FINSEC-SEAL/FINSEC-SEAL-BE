package com.finsecseal.release;

import tools.jackson.databind.JsonNode;
import com.finsecseal.common.domain.ArtifactType;
import com.finsecseal.common.domain.Sensitivity;
import com.finsecseal.common.persistence.UuidV7;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

@Entity
@Table(name = "release_artifacts")
public class ReleaseArtifactEntity {

    @Id
    private UUID id;

    @Column(name = "release_id", nullable = false, updatable = false)
    private UUID releaseId;

    @Enumerated(EnumType.STRING)
    @Column(name = "artifact_type", nullable = false, updatable = false, length = 40)
    private ArtifactType artifactType;

    @Column(nullable = false, updatable = false, length = 160)
    private String name;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "content_json", columnDefinition = "jsonb", updatable = false)
    private JsonNode contentJson;

    @Column(name = "content_text_encrypted", updatable = false)
    private String encryptedText;

    @Column(nullable = false, updatable = false, columnDefinition = "sha256_digest")
    private String sha256;

    @Column(name = "canonicalization_version", nullable = false, updatable = false, length = 40)
    private String canonicalizationVersion;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, updatable = false, length = 30)
    private Sensitivity sensitivity;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    protected ReleaseArtifactEntity() {
    }

    public ReleaseArtifactEntity(
            UUID releaseId,
            ArtifactType artifactType,
            String name,
            JsonNode contentJson,
            String encryptedText,
            String sha256,
            Sensitivity sensitivity
    ) {
        this.releaseId = releaseId;
        this.artifactType = artifactType;
        this.name = name;
        this.contentJson = contentJson == null ? null : contentJson.deepCopy();
        this.encryptedText = encryptedText;
        this.sha256 = sha256;
        this.canonicalizationVersion = CanonicalJsonService.VERSION;
        this.sensitivity = sensitivity;
    }

    @PrePersist
    void prePersist() {
        if (id == null) {
            id = UuidV7.generate();
        }
        if (createdAt == null) {
            createdAt = Instant.now();
        }
    }

    public String getEncryptedText() {
        return encryptedText;
    }

    public String getSha256() {
        return sha256;
    }

    public ArtifactType getArtifactType() {
        return artifactType;
    }

    public String getName() {
        return name;
    }
}
