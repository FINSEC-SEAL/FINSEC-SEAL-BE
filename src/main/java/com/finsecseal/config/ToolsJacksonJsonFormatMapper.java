package com.finsecseal.config;

import java.lang.reflect.Type;
import org.hibernate.type.format.AbstractJsonFormatMapper;
import tools.jackson.databind.ObjectMapper;

/**
 * Forces Hibernate JSON columns to use the same tools.jackson type system used by Spring Boot 4.
 */
public class ToolsJacksonJsonFormatMapper extends AbstractJsonFormatMapper {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Override
    protected <T> T fromString(CharSequence charSequence, Type type) {
        try {
            return MAPPER.readValue(
                    charSequence.toString(),
                    MAPPER.getTypeFactory().constructType(type)
            );
        } catch (Exception exception) {
            throw new IllegalArgumentException(
                    "Could not deserialize string to java type: " + type,
                    exception
            );
        }
    }

    @Override
    protected <T> String toString(T value, Type type) {
        try {
            return MAPPER.writerFor(MAPPER.getTypeFactory().constructType(type))
                    .writeValueAsString(value);
        } catch (Exception exception) {
            throw new IllegalArgumentException(
                    "Could not serialize object of java type: " + type,
                    exception
            );
        }
    }
}
