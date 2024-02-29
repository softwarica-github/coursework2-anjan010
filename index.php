<!DOCTYPE html>
<html>
<head>
    <title>IDS Alerts Dashboard</title>
</head>
<body>
    <h1>Alerts</h1>
    <ul>
        {% for alert in alerts %}
            <li>{{ alert }}</li>
        {% endfor %}
    </ul>
</body>
</html>

