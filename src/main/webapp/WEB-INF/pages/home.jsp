<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<!DOCTYPE html>
<html>
<head>
    <title>Welcome!</title>
</head>

<body>
    <h1>Hello <b>${pageContext.request.userPrincipal.name}</b>!</h1>
    <form action="/logout" method="POST">
        <input type="submit" value="Sign Out"/>
        <input type="hidden" name="${_csrf.parameterName}" value="${_csrf.token}"/>
    </form>
</body>
</html>