package in.gov.cca.esign.util;

import jakarta.xml.bind.JAXBContext;
import jakarta.xml.bind.JAXBException;
import jakarta.xml.bind.Marshaller;
import jakarta.xml.bind.Unmarshaller;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.io.StringReader;
import java.io.StringWriter;
import java.util.concurrent.ConcurrentHashMap;

@Slf4j
@Component
public class XmlUtils {

    private final ConcurrentHashMap<Class<?>, JAXBContext> contextCache = new ConcurrentHashMap<>();

    public <T> String marshal(T object) {
        try {
            JAXBContext context = getContext(object.getClass());
            Marshaller marshaller = context.createMarshaller();
            marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, Boolean.TRUE);
            // JAXB RI emits the XML declaration by default (JAXB_FRAGMENT = false)

            StringWriter writer = new StringWriter();
            marshaller.marshal(object, writer);
            return writer.toString();
        } catch (JAXBException e) {
            log.error("Error marshalling object to XML", e);
            throw new RuntimeException("Failed to marshal XML", e);
        }
    }

    public <T> T unmarshal(String xml, Class<T> clazz) {
        try {
            JAXBContext context = getContext(clazz);
            Unmarshaller unmarshaller = context.createUnmarshaller();
            return clazz.cast(unmarshaller.unmarshal(new StringReader(xml)));
        } catch (JAXBException e) {
            log.error("Error unmarshalling XML to object", e);
            throw new RuntimeException("Failed to unmarshal XML", e);
        }
    }

    private JAXBContext getContext(Class<?> clazz) {
        return contextCache.computeIfAbsent(clazz, k -> {
            try {
                return JAXBContext.newInstance(clazz);
            } catch (JAXBException e) {
                throw new RuntimeException("Failed to create JAXBContext for " + clazz.getName(), e);
            }
        });
    }
}