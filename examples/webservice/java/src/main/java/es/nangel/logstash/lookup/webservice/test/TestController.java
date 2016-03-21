package es.nangel.logstash.lookup.webservice.test;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
public class TestController {

    @RequestMapping(value = "/json", produces = "application/json")
    public Map<String, String> getElementJSON() {
        Map<String, String> toReturn = new HashMap<>();
        toReturn.put("200", "OK");
        return toReturn;
    }
}