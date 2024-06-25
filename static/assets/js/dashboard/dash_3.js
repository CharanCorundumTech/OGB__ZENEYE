try {
  /*
    ==============================
    |    @Options Charts Script   |
    ==============================
*/

  /*
    =============================
        Daily Sales | Options
    =============================
*/
  document.addEventListener("DOMContentLoaded", function () {
    // Make an AJAX request to your Flask API endpoint
    fetch("hightes_amount_yearly")
      .then((response) => {
        if (!response.ok) {
          throw new Error("Network response was not ok");
        }
        return response.json();
      })
      .then((data) => {
        // Data is available here, use it to initialize your chart
        var accountno = data.account_numbers;
        var amount = data.transaction_amounts;
        var d_2options1 = {
          chart: {
            height: 160,
            type: "bar",
            stacked: true,
            stackType: "100%",
            toolbar: {
              show: false,
            },
          },
          dataLabels: {
            enabled: false,
          },
          stroke: {
            show: true,
            width: 1,
          },
          colors: ["#dc3545", "#e0e6ed"],
          responsive: [
            {
              breakpoint: 480,
              options: {
                legend: {
                  position: "bottom",
                  offsetX: -10,
                  offsetY: 0,
                },
              },
            },
          ],
          series: [
            {
              name: "Account Number",
              data: accountno,
            },
            {
              name: "Transaction Amount",
              data: amount,
            },
          ],
          xaxis: {
            labels: {
              show: false,
            },
            categories: amount,
          },
          yaxis: {
            show: false,
          },
          fill: {
            opacity: 1,
          },
          plotOptions: {
            bar: {
              horizontal: false,
              endingShape: "rounded",
              columnWidth: "25%",
            },
          },
          legend: {
            show: false,
          },
          grid: {
            show: false,
            xaxis: {
              lines: {
                show: false,
              },
            },
            padding: {
              top: 10,
              right: 0,
              bottom: -40,
              left: 0,
            },
          },
        };
        var d_2C_1 = new ApexCharts(
          document.querySelector("#daily-sales"),
          d_2options1
        );
        d_2C_1.render();
      })

      .catch((error) => console.error("Error:", error));
  });

  document.addEventListener("DOMContentLoaded", function () {
    // Make an AJAX request to your Flask API endpoint
    fetch("lowest_amount_yearly")
      .then((response) => {
        if (!response.ok) {
          throw new Error("Network response was not ok");
        }
        return response.json();
      })
      .then((data) => {
        // Data is available here, use it to initialize your chart
        var accountno = data.account_numbers;
        var amount = data.transaction_amounts;
        var d_2options1 = {
          chart: {
            height: 260,
            type: "bar",
            stacked: true,
            stackType: "100%",
            toolbar: {
              show: false,
            },
          },
          dataLabels: {
            enabled: false,
          },
          stroke: {
            show: true,
            width: 1,
          },
          colors: ["#dc3545", "#e0e6ed"],
          responsive: [
            {
              breakpoint: 480,
              options: {
                legend: {
                  position: "bottom",
                  offsetX: -10,
                  offsetY: 0,
                },
              },
            },
          ],
          series: [
            {
              name: "Account Number",
              data: accountno,
            },
            {
              name: "Transaction Amount",
              data: amount,
            },
          ],
          xaxis: {
            labels: {
              show: false,
            },
            categories: amount,
          },
          yaxis: {
            show: false,
          },
          fill: {
            opacity: 1,
          },
          plotOptions: {
            bar: {
              horizontal: false,
              endingShape: "rounded",
              columnWidth: "25%",
            },
          },
          legend: {
            show: false,
          },
          grid: {
            show: false,
            xaxis: {
              lines: {
                show: false,
              },
            },
            padding: {
              top: 10,
              right: 0,
              bottom: -40,
              left: 0,
            },
          },
        };
        var d_2C_1 = new ApexCharts(
          document.querySelector("#daily-sales1"),
          d_2options1
        );
        d_2C_1.render();
      })

      .catch((error) => console.error("Error:", error));
  });

  /*
    =============================
        Total Orders | Options
    =============================
*/
  document.addEventListener("DOMContentLoaded", function () {
    // Make an AJAX request to your Flask API endpoint
    fetch("accounts_created_count")
      .then((response) => {
        if (!response.ok) {
          throw new Error("Network response was not ok");
        }
        return response.json();
      })
      .then((data) => {
        // Data is available here, use it to initialize your chart
        // var months = data.months;
        var months = [
          "January",
          "February",
          "March",
          "April",
          "May",
          "June",
          "July",
          "August",
          "September",
          "October",
          "November",
          "December",
        ];
        var counts = data.counts;
        var d_2options2 = {
          chart: {
            id: "sparkline1",
            group: "sparklines",
            type: "area",
            height: 280,
            sparkline: {
              enabled: true,
            },
          },
          stroke: {
            curve: "smooth",
            width: 2,
          },
          fill: {
            opacity: 1,
          },
          series: [
            {
              name: "Accounts Created in 2015 as per Month",
              data: counts,
            },
          ],
          labels: months,
          yaxis: {
            min: 0,
            labels: {
              // Set the same minWidth value for all charts that are synchronized
              minWidth: 50, // Adjust this value as needed
            },
          },
          grid: {
            padding: {
              top: 125,
              right: 0,
              bottom: 36,
              left: 0,
            },
          },
          fill: {
            type: "gradient",
            gradient: {
              type: "vertical",
              shadeIntensity: 1,
              inverseColors: !1,
              opacityFrom: 0.4,
              opacityTo: 0.05,
              stops: [45, 100],
            },
          },
          tooltip: {
            x: {
              show: true,
              formatter: function (value) {
                // Use the value as an index to get the corresponding month name
                console.log("Value:", value); // Add this line
                return months[value - 1];
              },
            },
            theme: "dark",
          },
          colors: ["#fff"],
        };
        var d_2C_2 = new ApexCharts(
          document.querySelector("#total-orders"),
          d_2options2
        );
        d_2C_2.render();
      })

      .catch((error) => console.error("Error:", error));
  });

  /*
    =================================
        Revenue Monthly | Options
    =================================
*/
  document.addEventListener("DOMContentLoaded", function () {
    // Make an AJAX request to your Flask API endpoint
    fetch("revenue")
      .then((response) => {
        if (!response.ok) {
          throw new Error("Network response was not ok");
        }
        return response.json();
      })
      .then((data) => {
        // Data is available here, use it to initialize your chart
        var depositData = data.deposit_data;
        var withdrawalData = data.withdrawal_data;

        var options1 = {
          chart: {
            fontFamily: "Nunito, sans-serif",
            height: 365,
            type: "area",
            zoom: {
              enabled: false,
            },
            dropShadow: {
              enabled: true,
              opacity: 0.3,
              blur: 5,
              left: -7,
              top: 22,
            },
            toolbar: {
              show: false,
            },
            events: {
              mounted: function (ctx, config) {
                const highest1 = ctx.getHighestValueInSeries(0);
                const highest2 = ctx.getHighestValueInSeries(1);

                ctx.addPointAnnotation({
                  x: new Date(
                    ctx.w.globals.seriesX[0][
                      ctx.w.globals.series[0].indexOf(highest1)
                    ]
                  ).getTime(),
                  y: highest1,
                  label: {
                    style: {
                      cssClass: "d-none",
                    },
                  },
                  customSVG: {
                    SVG: '<svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="#00579c" stroke="#fff" stroke-width="3" stroke-linecap="round" stroke-linejoin="round" class="feather feather-circle"><circle cx="12" cy="12" r="10"></circle></svg>',
                    cssClass: undefined,
                    offsetX: -8,
                    offsetY: 5,
                  },
                });

                ctx.addPointAnnotation({
                  x: new Date(
                    ctx.w.globals.seriesX[1][
                      ctx.w.globals.series[1].indexOf(highest2)
                    ]
                  ).getTime(),
                  y: highest2,
                  label: {
                    style: {
                      cssClass: "d-none",
                    },
                  },
                  customSVG: {
                    SVG: '<svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="#e7515a" stroke="#fff" stroke-width="3" stroke-linecap="round" stroke-linejoin="round" class="feather feather-circle"><circle cx="12" cy="12" r="10"></circle></svg>',
                    cssClass: undefined,
                    offsetX: -8,
                    offsetY: 5,
                  },
                });
              },
            },
          },
          colors: ["#00579c", "#e7515a"],
          dataLabels: {
            enabled: false,
          },
          markers: {
            discrete: [
              {
                seriesIndex: 0,
                dataPointIndex: 7,
                fillColor: "#000",
                strokeColor: "#000",
                size: 5,
              },
              {
                seriesIndex: 2,
                dataPointIndex: 11,
                fillColor: "#000",
                strokeColor: "#000",
                size: 2,
              },
            ],
          },
          subtitle: {
            text: "Overall WithDrawals & Deposits",
            align: "left",
            margin: 0,
            offsetX: -10,
            offsetY: 35,
            floating: false,
            style: {
              fontSize: "14px",
              color: "#888ea8",
            },
          },
          title: {
            text: "200000",
            align: "left",
            margin: 0,
            offsetX: -10,
            offsetY: 0,
            floating: false,
            style: {
              fontSize: "25px",
              color: "#0e1726",
            },
          },
          stroke: {
            show: true,
            curve: "smooth",
            width: 2,
            lineCap: "square",
          },
          series: [
            {
              name: "Deposits",
              data: depositData,
              //   [
              //   16800, 16800, 15500, 17800, 15500, 17000, 19000, 16000, 15000,
              //   17000, 14000, 17000,
              // ],
            },
            {
              name: "WithDrawals",
              data: withdrawalData,
              //   [
              //   16500, 17500, 16200, 17300, 16000, 19500, 16000, 17000, 16000,
              //   19000, 18000, 19000,
              // ],
            },
          ],
          labels: [
            "Jan",
            "Feb",
            "Mar",
            "Apr",
            "May",
            "Jun",
            "Jul",
            "Aug",
            "Sep",
            "Oct",
            "Nov",
            "Dec",
          ],
          xaxis: {
            axisBorder: {
              show: false,
            },
            axisTicks: {
              show: false,
            },
            crosshairs: {
              show: true,
            },
            labels: {
              offsetX: 0,
              offsetY: 5,
              style: {
                fontSize: "12px",
                fontFamily: "Nunito, sans-serif",
                cssClass: "apexcharts-xaxis-title",
              },
            },
          },
          yaxis: {
            labels: {
              formatter: function (value, index) {
                return value / 1000 + "K";
              },
              offsetX: -22,
              offsetY: 0,
              style: {
                fontSize: "12px",
                fontFamily: "Nunito, sans-serif",
                cssClass: "apexcharts-yaxis-title",
              },
            },
          },
          grid: {
            borderColor: "#e0e6ed",
            strokeDashArray: 5,
            xaxis: {
              lines: {
                show: true,
              },
            },
            yaxis: {
              lines: {
                show: false,
              },
            },
            padding: {
              top: 0,
              right: 0,
              bottom: 0,
              left: -10,
            },
          },
          legend: {
            position: "top",
            horizontalAlign: "right",
            offsetY: -50,
            fontSize: "16px",
            fontFamily: "Nunito, sans-serif",
            markers: {
              width: 10,
              height: 10,
              strokeWidth: 0,
              strokeColor: "#fff",
              fillColors: undefined,
              radius: 12,
              onClick: undefined,
              offsetX: 0,
              offsetY: 0,
            },
            itemMargin: {
              horizontal: 0,
              vertical: 20,
            },
          },
          tooltip: {
            theme: "dark",
            marker: {
              show: true,
            },
            x: {
              show: false,
            },
          },
          fill: {
            type: "gradient",
            gradient: {
              type: "vertical",
              shadeIntensity: 1,
              inverseColors: !1,
              opacityFrom: 0.28,
              opacityTo: 0.05,
              stops: [45, 100],
            },
          },
          responsive: [
            {
              breakpoint: 575,
              options: {
                legend: {
                  offsetY: -30,
                },
              },
            },
          ],
        };
        var chart1 = new ApexCharts(
          document.querySelector("#revenueMonthly"),
          options1
        );

        chart1.render();
      })

      .catch((error) => console.error("Error:", error));
  });
  /*
    ==================================
        Sales By Category | Options
    ==================================
*/
  document.addEventListener("DOMContentLoaded", function () {
    // Make an AJAX request to your Flask API endpoint
    fetch("no_accouts")
      .then((response) => {
        if (!response.ok) {
          throw new Error("Network response was not ok");
        }
        return response.json();
      })
      .then((data) => {
        // Data is available here, use it to initialize your chart
        // var depositData = data.deposit_data;
        var accounts = data.counts;
        var options = {
          chart: {
            type: "donut",
            width: 380,
          },
          colors: ["#5c1ac3", "#e2a03f", "#e7515a", "#e2a03f"],
          dataLabels: {
            enabled: false,
          },
          legend: {
            position: "bottom",
            horizontalAlign: "center",
            fontSize: "14px",
            markers: {
              width: 10,
              height: 10,
            },
            itemMargin: {
              horizontal: 0,
              vertical: 8,
            },
          },
          plotOptions: {
            pie: {
              donut: {
                size: "65%",
                background: "transparent",
                labels: {
                  show: true,
                  name: {
                    show: true,
                    fontSize: "29px",
                    fontFamily: "Nunito, sans-serif",
                    color: undefined,
                    offsetY: -10,
                  },
                  value: {
                    show: true,
                    fontSize: "26px",
                    fontFamily: "Nunito, sans-serif",
                    color: "20",
                    offsetY: 16,
                    formatter: function (val) {
                      return val;
                    },
                  },
                  total: {
                    show: true,
                    showAlways: true,
                    label: "Total",
                    color: "#888ea8",
                    formatter: function (w) {
                      return w.globals.seriesTotals.reduce(function (a, b) {
                        return a + b;
                      }, 0);
                    },
                  },
                },
              },
            },
          },
          stroke: {
            show: true,
            width: 25,
          },
          series: accounts,
          labels: ["Savings ", "Current", "Others"],
          responsive: [
            {
              breakpoint: 1599,
              options: {
                chart: {
                  width: "350px",
                  height: "400px",
                },
                legend: {
                  position: "bottom",
                },
              },

              breakpoint: 1439,
              options: {
                chart: {
                  width: "250px",
                  height: "390px",
                },
                legend: {
                  position: "bottom",
                },
                plotOptions: {
                  pie: {
                    donut: {
                      size: "65%",
                    },
                  },
                },
              },
            },
          ],
        };
        var chart = new ApexCharts(document.querySelector("#chart-2"), options);

        chart.render();
      })

      .catch((error) => console.error("Error:", error));
  });
  /*
    ==============================
    |    @Render Charts Script    |
    ==============================
*/

  /*
    ============================
        Daily Sales | Render
    ============================
*/

  /*
    ============================
        Total Orders | Render
    ============================
*/

  /*
    ================================
        Revenue Monthly | Render
    ================================
*/

  /*
    =================================
        Sales By Category | Render
    =================================
*/

  /*
    =============================================
        Perfect Scrollbar | Recent Activities
    =============================================
*/
  const ps = new PerfectScrollbar(document.querySelector(".mt-container"));
} catch (e) {
  console.log(e);
}
