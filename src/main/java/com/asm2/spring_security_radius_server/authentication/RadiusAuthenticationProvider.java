package com.asm2.spring_security_radius_server.authentication;

import java.util.ArrayList;
import java.util.List;

import jakarta.annotation.PostConstruct;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.tinyradius.packet.RadiusPacket;

/**
 * Component responsible for authentication against radius server
 */
public class RadiusAuthenticationProvider implements AuthenticationProvider {

	private static final Logger logger = LoggerFactory.getLogger(RadiusAuthenticationProvider.class);

	@Value("${com.asm2.radius.server}")
	private String serverConfigurationToken;

	private List<NetworkAccessServer> clients = new ArrayList<>();

	@PostConstruct
	public void initServers() {
		List<RadiusServer> servers = RadiusUtil.parseServerConfigurationToken(serverConfigurationToken);
		servers.forEach(it -> {
			clients.add(new NetworkAccessServer(it));
		});
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		String userName = authentication.getName();
		RadiusPacket response = null;
		int attemptCount = 0;
		while (response == null && attemptCount++ < clients.size()) {
			response = authenticateInternally(clients.get(attemptCount - 1), userName,
					authentication.getCredentials().toString());
		}
		if (response == null) {
			logger.warn("User {} calling but radius does not return any value.", userName);
			return null;
		}
		if (response.getPacketType() == RadiusPacket.ACCESS_ACCEPT) {
			logger.info("User {} successfully authenticated using radius.", userName);
			return new UsernamePasswordAuthenticationToken(userName, "", new ArrayList<>());
		} else {
			logger.warn("User {}, returned response {}.", userName, response);
			return null;
		}
	}

	private RadiusPacket authenticateInternally(NetworkAccessServer client, String userName, String password) {
		logger.info("Calling radius server to authenticate user {}.", userName);
		try {
			return client.authenticate(userName, password);
		} catch (Exception e) {
			logger.error("Exception when calling remote radius server.", e);
			return null;
		}
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return authentication.equals(UsernamePasswordAuthenticationToken.class);
	}
}
