var map = L.map('map').setView([20, 0], 2);

// Base map
L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
    attribution: '&copy; OpenStreetMap contributors'
}).addTo(map);

// Load logs
fetch("/api/logs")
.then(res => res.json())
.then(data => {

    console.log("Logs loaded for map:", data);

    data.forEach(log => {

        let message = log[1];
        let threat = log[2];
        let geo = log[3];

        if (!geo || geo === "None - None") return;

        // Expected format:
        // "Location | lat | lon"
        let parts = geo.split("|");

        if (parts.length !== 3) return;

        let location = parts[0].trim();
        let lat = parseFloat(parts[1].trim());
        let lon = parseFloat(parts[2].trim());

        if (isNaN(lat) || isNaN(lon)) return;

        // Only mark High threats (optional)
        if (threat !== "High") return;

        console.log("Adding marker:", location, lat, lon);

        L.circleMarker([lat, lon], {
            radius: 8,
            color: "#ef4444",
            fillColor: "#ef4444",
            fillOpacity: 0.8
        })
        .addTo(map)
        .bindPopup(`
            <b>Threat:</b> ${threat}<br>
            <b>Location:</b> ${location}<br>
            <b>Log:</b> ${message}
        `);
    });
});
