package com.finsecseal.release;

import com.finsecseal.common.domain.ArtifactType;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ReleaseArtifactRepository extends JpaRepository<ReleaseArtifactEntity, UUID> {

    List<ReleaseArtifactEntity> findAllByReleaseId(UUID releaseId);

    Optional<ReleaseArtifactEntity> findByReleaseIdAndArtifactTypeAndName(
            UUID releaseId,
            ArtifactType artifactType,
            String name
    );
}
