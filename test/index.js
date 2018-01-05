"use strict";

// Load modules

var Code = require("code");
var Lab = require("lab");
var Hapi = require("hapi");

// Declare internals

var internals = {};

internals.permissionsFunc = function(credentials, callback) {
  var userPermissions = {
    cars: {
      read: true,
      create: false,
      edit: true,
      delete: true
    },
    drivers: {
      read: true,
      create: false,
      edit: false,
      delete: false
    },
    abilities: {
      read: false,
      create: false,
      edit: false,
      delete: false
    }
  };

  callback(null, userPermissions);
};

// Test shortcuts

var lab = (exports.lab = Lab.script());
var before = lab.before;
var beforeEach = lab.beforeEach;
var after = lab.after;
var describe = lab.describe;
var it = lab.it;
var expect = Code.expect;

describe("hapi-route-acl", () => {
  describe("registration", () => {
    var server;

    beforeEach(() => {
      server = new Hapi.Server();
      server.start();
    });

    it("should return an error if options.permissionsFunc is not defined", async () => {
      try {
        await server.register({
          plugin: require("./../")
        });
      } catch (err) {
        expect(err).to.exist();
      }
    });

    it("should return an error if options.permissionsFunc is not a function", async () => {
      try {
        await server.register({
          plugin: require("./../"),
          options: {
            permissionsFunc: 123
          }
        });
      } catch (err) {
        expect(err).to.exist();
      }
    });
  });

  describe("route protection", function() {
    var server;

    beforeEach(() => {
      server = new Hapi.Server();
      server
        .register({
          plugin: require("./../"),
          options: {
            permissionsFunc: internals.permissionsFunc
          }
        })
        .then(() => {
          server.start();
        });
    });

    it("should allow access to a route if plugin configuration is not defined in route config", async () => {
      server.route({
        method: "GET",
        path: "/unprotected1",
        config: {
          handler: function(request, h) {
            return "hola mi amigo";
          }
        }
      });
      let res = await server.inject({
        method: "GET",
        url: "/unprotected1"
      });
      expect(res.statusCode).to.equal(200);
    });

    it("should allow access to a route if required permission array is empty", async () => {
      server.route({
        method: "GET",
        path: "/unprotected2",
        config: {
          handler: function(request, h) {
            return "como estas?";
          },
          plugins: {
            hapiRouteAcl: {
              permissions: []
            }
          }
        }
      });
      let res = await server.inject({
        method: "GET",
        url: "/unprotected2"
      });
      expect(res.statusCode).to.equal(200);
    });

    it("should allow access to a route if user has permission", async () => {
      server.route({
        method: "GET",
        path: "/cars",
        config: {
          handler: function(request, h) {
            return ["Toyota Camry", "Honda Accord", "Ford Fusion"];
          },
          plugins: {
            hapiRouteAcl: {
              permissions: ["cars:read"]
            }
          }
        }
      });
      let res = await server.inject({
        method: "GET",
        url: "/cars"
      });
      expect(res.statusCode).to.equal(200);
    });

    it("should allow access for permissions defined as a string", async () => {
      server.route({
        method: "GET",
        path: "/cars/{id}",
        config: {
          handler: function(request, h) {
            return "Toyota Camry";
          },
          plugins: {
            hapiRouteAcl: {
              permissions: "cars:read"
            }
          }
        }
      });
      let res = await server.inject({
        method: "GET",
        url: "/cars/1"
      });
      expect(res.statusCode).to.equal(200);
    });

    it("should deny access to a route if user does not have permission", async () => {
      server.route({
        method: "POST",
        path: "/cars",
        config: {
          handler: function(request, h) {
            return "car created!";
          },
          plugins: {
            hapiRouteAcl: {
              permissions: ["cars:create"]
            }
          }
        }
      });
      let res = await server.inject({
        method: "POST",
        url: "/cars"
      });
      expect(res.statusCode).to.equal(401);
    });

    it("should throw an exception if route permission is not a string", async () => {
      server.ext(
        "onPostAuth",
        function(request, h) {
          request.domain.on("error", function(error) {
            request.caughtError = error;
          });
          return h.continue;
        },
        {
          before: ["hapi-route-acl"]
        }
      );

      server.route({
        method: "GET",
        path: "/cars",
        config: {
          handler: function(request, h) {
            ["Toyota Camry", "Honda Accord", "Ford Fusion"];
          },
          plugins: {
            hapiRouteAcl: {
              permissions: [12345]
            }
          }
        }
      });

      let res = await server.inject({
        method: "GET",
        url: "/cars"
      });
      var error = res.request.caughtError;

      expect(error).to.be.an.instanceof(Error);
      expect(error.message).to.equal(
        "Uncaught error: permission must be a string"
      );
    });

    it("should throw an exception if route permission is not formatted properly", async () => {
      server.ext(
        "onPostAuth",
        function(request, reply) {
          request.domain.on("error", function(error) {
            request.caughtError = error;
          });

          return reply.continue;
        },
        { before: ["hapi-route-acl"] }
      );

      server.route({
        method: "GET",
        path: "/cars",
        config: {
          handler: function(request, reply) {
            reply(["Toyota Camry", "Honda Accord", "Ford Fusion"]);
          },
          plugins: {
            hapiRouteAcl: {
              permissions: ["carsread"] // missing colon
            }
          }
        }
      });

      let res = await server.inject({
        method: "GET",
        url: "/cars"
      });
      var error = res.request.caughtError;
      expect(error).to.be.an.instanceof(Error);
      expect(error.message).to.equal(
        "Uncaught error: permission must be formatted: [routeName]:[read|create|edit|delete]"
      );
    });

    it("should deny access to a route if user permission is not defined for the route", async () => {
      server.route({
        method: "DELETE",
        path: "/foobar/{id}",
        config: {
          handler: function(request, h) {
            return "car deleted!";
          },
          plugins: {
            hapiRouteAcl: {
              permissions: ["foobar:delete"]
            }
          }
        }
      });
      let res = await server.inject({
        method: "DELETE",
        url: "/foobar/1"
      });
      expect(res.statusCode).to.equal(401);
    });

    it("should allow access to a route with multiple permission requirements if user has permissions", async () => {
      server.route({
        method: "GET",
        path: "/cars/{id}/drivers",
        config: {
          handler: function(request, h) {
            return ["Greg", "Tom", "Sam"];
          },
          plugins: {
            hapiRouteAcl: {
              permissions: ["cars:read", "drivers:read"]
            }
          }
        }
      });
      let res = await server.inject({
        method: "GET",
        url: "/cars/1/drivers"
      });
      expect(res.statusCode).to.equal(200);
    });

    it("should deny access to a route with two permission requirements if user does not have permissions", async () => {
      server.route({
        method: "DELETE",
        path: "/cars/{carId}/drivers/{driverId}",
        config: {
          handler: function(request, h) {
            return "driver deleted!";
          },
          plugins: {
            hapiRouteAcl: {
              permissions: ["drivers:delete", "cars:read"]
            }
          }
        }
      });
      let res = await server.inject({
        method: "DELETE",
        url: "/cars/1/drivers/1"
      });
      expect(res.statusCode).to.equal(401);
    });

    it("should deny access to a route with multiple permission requirements if user does not have permissions", async () => {
      server.route({
        method: "GET",
        path: "/cars/{carId}/drivers/{driverId}/abilities/{abilitiesId}",
        config: {
          handler: function(request, h) {
            return "driver deleted!";
          },
          plugins: {
            hapiRouteAcl: {
              permissions: ["drivers:read", "cars:read", "abilities:read"]
            }
          }
        }
      });
      let res = await server.inject({
        method: "GET",
        url: "/cars/1/drivers/1/abilities/1"
      });
      expect(res.statusCode).to.equal(401);
    });
  });
});
