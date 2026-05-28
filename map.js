const LIBRARY_CONFIG = {
  name: "40 Orchard View Blvd, Toronto",

  lat: 43.7082733,
  lng: -79.3999995,

  checkInRadiusKm: 0.5,
  checkInRadiusMeters: 500,

  earlyCheckInMinutes: 30,

  lateLimitMinutes: 15
};

if (typeof module !== "undefined") {
  module.exports = LIBRARY_CONFIG;
}