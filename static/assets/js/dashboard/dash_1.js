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
    colors: ["#e2a03f", "#e0e6ed"],
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
        name: "Sales",
        data: [44, 55, 41, 67, 22, 43, 21],
      },
      {
        name: "Last Week",
        data: [13, 23, 20, 8, 13, 27, 33],
      },
    ],
    xaxis: {
      labels: {
        show: false,
      },
      categories: ["Sun", "Mon", "Tue", "Wed", "Thur", "Fri", "Sat"],
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

  /*
    =============================
        Total Orders | Options
    =============================
*/
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
        name: "Sales",
        data: [28, 40, 36, 52, 38, 60, 38, 52, 36, 40],
      },
    ],
    labels: ["1", "2", "3", "4", "5", "6", "7", "8", "9", "10"],
    yaxis: {
      min: 0,
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
        show: false,
      },
      theme: "dark",
    },
    colors: ["#fff"],
  };

  /*
    =================================
        Revenue Monthly | Options
    =================================
*/

  // // Assuming you have the initial data available
  // options1.series[0].data = generatePendingSeriesData(
  //   options1.xaxis.categories,
  //   resultlist
  // );
  // options1.series[1].data = generateClosedSeriesData(
  //   options1.xaxis.categories,
  //   commentdata
  // );
  // options1.series[2].data = generateSentSeriesData(
  //   options1.xaxis.categories,
  //   caseperday
  // );

  // Example usage:
  // Call mlroCount with your data to update the chart
  // mlroCount(countValue, coutAcceptedSTRValue, countcommentedticketsValue, countSentBackCaseAlertsValue, countsArray, datesArray, commentdataArray);

  // var options1 = {
  //   chart: {
  //     fontFamily: "Nunito, sans-serif",
  //     height: 365,
  //     type: "area",
  //     zoom: {
  //       enabled: false,
  //     },
  //     dropShadow: {
  //       enabled: true,
  //       opacity: 0.3,
  //       blur: 5,
  //       left: -7,
  //       top: 22,
  //     },
  //     toolbar: {
  //       show: false,
  //     },
  //     events: {
  //       mounted: function (ctx, config) {
  //         const highest1 = ctx.getHighestValueInSeries(0);
  //         const highest2 = ctx.getHighestValueInSeries(1);

  //         ctx.addPointAnnotation({
  //           x: new Date(
  //             ctx.w.globals.seriesX[0][
  //               ctx.w.globals.series[0].indexOf(highest1)
  //             ]
  //           ).getTime(),
  //           y: highest1,
  //           label: {
  //             style: {
  //               cssClass: "d-none",
  //             },
  //           },
  //           // customSVG: {
  //           //     SVG: '<svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="#1b55e2" stroke="#fff" stroke-width="3" stroke-linecap="round" stroke-linejoin="round" class="feather feather-circle"><circle cx="12" cy="12" r="10"></circle></svg>',
  //           //     cssClass: undefined,
  //           //     offsetX: -8,
  //           //     offsetY: 5
  //           // }
  //         });

  //         ctx.addPointAnnotation({
  //           x: new Date(
  //             ctx.w.globals.seriesX[1][
  //               ctx.w.globals.series[1].indexOf(highest2)
  //             ]
  //           ).getTime(),
  //           y: highest2,
  //           label: {
  //             style: {
  //               cssClass: "d-none",
  //             },
  //           },
  //           // customSVG: {
  //           //     SVG: '<svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="#e7515a" stroke="#fff" stroke-width="3" stroke-linecap="round" stroke-linejoin="round" class="feather feather-circle"><circle cx="12" cy="12" r="10"></circle></svg>',
  //           //     cssClass: undefined,
  //           //     offsetX: -8,
  //           //     offsetY: 5
  //           // }
  //         });
  //       },
  //     },
  //   },
  //   colors: ["#00579C", "#C71007", "#098801"],
  //   dataLabels: {
  //     enabled: false,
  //   },
  //   markers: {
  //     discrete: [
  //       {
  //         seriesIndex: 0,
  //         dataPointIndex: 7,
  //         fillColor: "#000",
  //         strokeColor: "#000",
  //         size: 5,
  //       },
  //       {
  //         seriesIndex: 2,
  //         dataPointIndex: 11,
  //         fillColor: "#000",
  //         strokeColor: "#000",
  //         size: 4,
  //       },
  //     ],
  //   },
  //   title: {
  //     text: "5,000,00",
  //     align: "left",
  //     margin: 0,
  //     offsetX: -10,
  //     offsetY: 0,
  //     floating: false,
  //     style: {
  //       fontSize: "25px",
  //       color: "#fff",
  //     },
  //   },

  //   stroke: {
  //     show: true,
  //     curve: "smooth",
  //     width: 2,
  //     lineCap: "square",
  //   },
  //   series: [
  //     {
  //       name: "Pending",
  //       data: [
  //         6800, 1800, 5500, 1800, 1500, 7000, 9000, 6000, 5000, 1000, 1400,
  //         1700,
  //       ],
  //     },
  //     {
  //       name: "Closed",
  //       data: [
  //         1650, 1700, 1200, 1700, 1600, 1500, 6000, 1700, 6000, 1000, 8000,
  //         1900,
  //       ],
  //     },
  //     {
  //       name: "Sent",
  //       data: [
  //         1680, 1600, 1500, 1780, 1550, 1700, 1900, 1600, 1500, 1700, 1400,
  //         1700,
  //       ],
  //     },
  //   ],
  //   labels: [],
  //   xaxis: {
  //     axisBorder: {
  //       show: false,
  //     },
  //     axisTicks: {
  //       show: false,
  //     },
  //     crosshairs: {
  //       show: true,
  //     },
  //     labels: {
  //       offsetX: 0,
  //       offsetY: 5,
  //       style: {
  //         fontSize: "12px",
  //         fontFamily: "Nunito, sans-serif",
  //         cssClass: "apexcharts-xaxis-title",
  //       },
  //       formatter: function (value) {
  //         // Convert timestamp to date
  //         const date = new Date(value);
  //         // Format the date as DD-MM-YYYY
  //         const day = date.getDate().toString().padStart(2, "0");
  //         const month = (date.getMonth() + 1).toString().padStart(2, "0");
  //         return day + "-" + month + "-" + date.getFullYear();
  //       },
  //     },
  //   },
  //   yaxis: {
  //     labels: {
  //       formatter: function (value, index) {
  //         return value;
  //       },
  //       offsetX: -22,
  //       offsetY: 0,
  //       style: {
  //         fontSize: "12px",
  //         fontFamily: "Nunito, sans-serif",
  //         cssClass: "apexcharts-yaxis-title",
  //       },
  //     },
  //   },
  //   grid: {
  //     borderColor: "#e0e6ed",
  //     strokeDashArray: 5,
  //     xaxis: {
  //       lines: {
  //         show: true,
  //       },
  //     },
  //     yaxis: {
  //       lines: {
  //         show: false,
  //       },
  //     },
  //     padding: {
  //       top: 0,
  //       right: 0,
  //       bottom: 0,
  //       left: -10,
  //     },
  //   },
  //   legend: {
  //     position: "top",
  //     horizontalAlign: "right",
  //     offsetY: -50,
  //     fontSize: "16px",
  //     fontFamily: "Nunito, sans-serif",
  //     markers: {
  //       width: 10,
  //       height: 10,
  //       strokeWidth: 0,
  //       strokeColor: "#fff",
  //       fillColors: undefined,
  //       radius: 12,
  //       onClick: undefined,
  //       offsetX: 0,
  //       offsetY: 0,
  //     },
  //     itemMargin: {
  //       horizontal: 0,
  //       vertical: 20,
  //     },
  //   },
  //   tooltip: {
  //     theme: "dark",
  //     marker: {
  //       show: true,
  //     },
  //     x: {
  //       show: false,
  //     },
  //   },
  //   fill: {
  //     type: "gradient",
  //     gradient: {
  //       type: "vertical",
  //       shadeIntensity: 1,
  //       inverseColors: !1,
  //       opacityFrom: 0.28,
  //       opacityTo: 0.05,
  //       stops: [45, 100],
  //     },
  //   },
  //   responsive: [
  //     {
  //       breakpoint: 575,
  //       options: {
  //         legend: {
  //           offsetY: -30,
  //         },
  //       },
  //     },
  //   ],
  // };

  // // Generate labels for the previous 10 days and the next day
  // const currentDate = new Date(); // Current date
  // const labels = [];
  // for (let i = 11; i >= 0; i--) {
  //   const previousDate = new Date(currentDate);
  //   previousDate.setDate(currentDate.getDate() - i);
  //   labels.push(previousDate.getTime());
  // }

  // options1.labels = labels;

  // var options1 = {
  //   chart: {
  //     fontFamily: "Nunito, sans-serif",
  //     height: 365,
  //     type: "area",
  //     zoom: {
  //       enabled: false,
  //     },
  //     dropShadow: {
  //       enabled: true,
  //       opacity: 0.3,
  //       blur: 5,
  //       left: -7,
  //       top: 22,
  //     },
  //     toolbar: {
  //       show: false,
  //     },
  //     events: {
  //       mounted: function (ctx, config) {
  //         const highest1 = ctx.getHighestValueInSeries(0);
  //         const highest2 = ctx.getHighestValueInSeries(1);

  //         ctx.addPointAnnotation({
  //           x: new Date(
  //             ctx.w.globals.seriesX[0][
  //               ctx.w.globals.series[0].indexOf(highest1)
  //             ]
  //           ).getTime(),
  //           y: highest1,
  //           label: {
  //             style: {
  //               cssClass: "d-none",
  //             },
  //           },
  //           // customSVG: {
  //           //     SVG: '<svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="#1b55e2" stroke="#fff" stroke-width="3" stroke-linecap="round" stroke-linejoin="round" class="feather feather-circle"><circle cx="12" cy="12" r="10"></circle></svg>',
  //           //     cssClass: undefined,
  //           //     offsetX: -8,
  //           //     offsetY: 5
  //           // }
  //         });

  //         ctx.addPointAnnotation({
  //           x: new Date(
  //             ctx.w.globals.seriesX[1][
  //               ctx.w.globals.series[1].indexOf(highest2)
  //             ]
  //           ).getTime(),
  //           y: highest2,
  //           label: {
  //             style: {
  //               cssClass: "d-none",
  //             },
  //           },
  //           // customSVG: {
  //           //     SVG: '<svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="#e7515a" stroke="#fff" stroke-width="3" stroke-linecap="round" stroke-linejoin="round" class="feather feather-circle"><circle cx="12" cy="12" r="10"></circle></svg>',
  //           //     cssClass: undefined,
  //           //     offsetX: -8,
  //           //     offsetY: 5
  //           // }
  //         });
  //       },
  //     },
  //   },
  //   colors: ["#009688", "#00579c"],
  //   dataLabels: {
  //     enabled: false,
  //   },
  //   markers: {
  //     discrete: [
  //       {
  //         seriesIndex: 0,
  //         dataPointIndex: 7,
  //         fillColor: "#000",
  //         strokeColor: "#000",
  //         size: 5,
  //       },
  //       {
  //         seriesIndex: 2,
  //         dataPointIndex: 11,
  //         fillColor: "#000",
  //         strokeColor: "#000",
  //         size: 4,
  //       },
  //     ],
  //   },
  //   subtitle: {
  //     text: "Total Alerts/month",
  //     align: "left",
  //     margin: 0,
  //     offsetX: -10,
  //     offsetY: 35,
  //     floating: false,
  //     style: {
  //       fontSize: "14px",
  //       color: "#888ea8",
  //     },
  //   },
  //   title: {
  //     text: "5,000,00",
  //     align: "left",
  //     margin: 0,
  //     offsetX: -10,
  //     offsetY: 0,
  //     floating: false,
  //     style: {
  //       fontSize: "25px",
  //       color: "#0e1726",
  //     },
  //   },
  //   stroke: {
  //     show: true,
  //     curve: "smooth",
  //     width: 2,
  //     lineCap: "square",
  //   },
  //   series: [
  //     {
  //       name: "Alerts raised",
  //       data: [
  //         16800, 16800, 15500, 17800, 15500, 17000, 19000, 16000, 15000, 17000,
  //         14000, 17000,
  //       ],
  //     },
  //     {
  //       name: "Alerts sent to next level officer",
  //       data: [
  //         16500, 17500, 16200, 17300, 16000, 19500, 16000, 17000, 16000, 19000,
  //         18000, 19000,
  //       ],
  //     },
  //   ],
  //   labels: [
  //     "Jan",
  //     "Feb",
  //     "Mar",
  //     "Apr",
  //     "May",
  //     "Jun",
  //     "Jul",
  //     "Aug",
  //     "Sep",
  //     "Oct",
  //     "Nov",
  //     "Dec",
  //   ],
  //   xaxis: {
  //     axisBorder: {
  //       show: false,
  //     },
  //     axisTicks: {
  //       show: false,
  //     },
  //     crosshairs: {
  //       show: true,
  //     },
  //     labels: {
  //       offsetX: 0,
  //       offsetY: 5,
  //       style: {
  //         fontSize: "12px",
  //         fontFamily: "Nunito, sans-serif",
  //         cssClass: "apexcharts-xaxis-title",
  //       },
  //     },
  //   },
  //   yaxis: {
  //     labels: {
  //       formatter: function (value, index) {
  //         return value;
  //       },
  //       offsetX: -22,
  //       offsetY: 0,
  //       style: {
  //         fontSize: "12px",
  //         fontFamily: "Nunito, sans-serif",
  //         cssClass: "apexcharts-yaxis-title",
  //       },
  //     },
  //   },
  //   grid: {
  //     borderColor: "#e0e6ed",
  //     strokeDashArray: 5,
  //     xaxis: {
  //       lines: {
  //         show: true,
  //       },
  //     },
  //     yaxis: {
  //       lines: {
  //         show: false,
  //       },
  //     },
  //     padding: {
  //       top: 0,
  //       right: 0,
  //       bottom: 0,
  //       left: -10,
  //     },
  //   },
  //   legend: {
  //     position: "top",
  //     horizontalAlign: "right",
  //     offsetY: -50,
  //     fontSize: "16px",
  //     fontFamily: "Nunito, sans-serif",
  //     markers: {
  //       width: 10,
  //       height: 10,
  //       strokeWidth: 0,
  //       strokeColor: "#fff",
  //       fillColors: undefined,
  //       radius: 12,
  //       onClick: undefined,
  //       offsetX: 0,
  //       offsetY: 0,
  //     },
  //     itemMargin: {
  //       horizontal: 0,
  //       vertical: 20,
  //     },
  //   },
  //   tooltip: {
  //     theme: "dark",
  //     marker: {
  //       show: true,
  //     },
  //     x: {
  //       show: false,
  //     },
  //   },
  //   fill: {
  //     type: "gradient",
  //     gradient: {
  //       type: "vertical",
  //       shadeIntensity: 1,
  //       inverseColors: !1,
  //       opacityFrom: 0.28,
  //       opacityTo: 0.05,
  //       stops: [45, 100],
  //     },
  //   },
  //   responsive: [
  //     {
  //       breakpoint: 575,
  //       options: {
  //         legend: {
  //           offsetY: -30,
  //         },
  //       },
  //     },
  //   ],
  // };

  /*
    ==================================
        Sales By Category | Options
    ==================================
*/

  function itCount(count, countSubmited, perdayDatait) {
    if (count == undefined) {
      options.series[0] = 0;
      options8.series[0] = 0;
      optionsmonthlyit.series = [];
    } else {
      options.series[0] = count;
      options8.series[0] = countSubmited;
      optionsmonthlyit.series[0] = {
        name: "Sent",
        data: itperdayDatamonthly(
          optionsmonthlyit.xaxis.categories,
          perdayDatait
        ),
      };
    }
  }

  function mlroCount(
    count,
    coutAcceptedSTR,
    countcommentedtickets,
    countSentBackCaseAlerts,
    resultlist,
    commentdata,
    caseperday
  ) {
    if (count === undefined) {
      // Handle the case where data is undefined
      options.series[0] = 0;
      options5.series[0] = 0;
      optionsmlro.series[0] = 0;
      optionsmlro.series[1] = 0;
      optionsmlro.series[2] = 0;
      optionsmlro.series[3] = 0;
      options1.series = [];
    } else {
      // Update main data series
      options.series[0] = count;
      options5.series[0] = coutAcceptedSTR;
      optionsmlro.series[0] = count;
      optionsmlro.series[1] = coutAcceptedSTR;
      optionsmlro.series[2] = countcommentedtickets;
      optionsmlro.series[3] = countSentBackCaseAlerts;
      options1.series[0] = {
        name: "Pending",
        data: generatePendingSeriesData(options1.xaxis.categories, resultlist),
      };
      options1.series[1] = {
        name: "Closed",
        data: generateClosedSeriesData(options1.xaxis.categories, commentdata),
      };
      options1.series[2] = {
        name: "Sent",
        data: generateSentSeriesData(options1.xaxis.categories, caseperday),
      };
    }
  }

  function cmCount(
    count,
    coutAcceptedSTR,
    countcommentedtickets,
    countSentBackCaseAlerts,
    allocateresultlist,
    caseresultlist
  ) {
    if (count == undefined) {
      options.series[0] = 0;
      options6.series[0] = 0;
      optionscm.series[0] = 0;
      optionscm.series[1] = 0;
      optionscm.series[2] = 0;
      optionscm.series[3] = 0;
      optionsmonthlycm.series = [];

      // options6.series[1] = 0;
    } else {
      options.series[0] = count;
      options6.series[0] = coutAcceptedSTR;
      optionscm.series[0] = count;
      optionscm.series[1] = coutAcceptedSTR;
      optionscm.series[2] = countcommentedtickets;
      optionscm.series[3] = countSentBackCaseAlerts;
      optionsmonthlycm.series[0] = {
        name: "Pending",
        data: allocateresultlistData(
          options1.xaxis.categories,
          allocateresultlist
        ),
      };
      optionsmonthlycm.series[1] = {
        name: "sent",
        data: caseresultlistData(options1.xaxis.categories, caseresultlist),
      };

      // options6.series[1] = coutAcceptedNONSTR10;
    }
  }
  // optionsmonthlycm
  //  agm offlline dashboard
  function agmofflineCount(
    count,
    countSubmited,
    assignedperdayagm,
    submittedperdayagm
  ) {
    if (count == undefined) {
      options12.series[0] = 0;
      options12.series[1] = 0;
      optionsmonthlyros.series = [];
    } else {
      options12.series[0] = count;
      options12.series[1] = countSubmited;
      optionsmonthlyros.series[0] = {
        name: "Pending",
        data: assignedperdayDataOfflineagm(
          options1.xaxis.categories,
          assignedperdayagm
        ),
      };
      optionsmonthlyros.series[1] = {
        name: "sent",
        data: submittedperdayDataOfflineagm(
          options1.xaxis.categories,
          submittedperdayagm
        ),
      };
    }
  }

  // agm dashboard

  function agmCount(
    count,
    countSubmited,
    countSentBackCaseAlerts,
    allocatedperday,
    caseticketsperday,
    coutAcceptedNONSTR10
  ) {
    if (count == undefined) {
      options.series[0] = 0;
      options7.series[0] = 0;
      optionsagm.series[0] = 0;
      optionsagm.series[1] = 0;
      optionsagm.series[2] = 0;
      optionsmonthlycm.series = [];

      // options7.series[1] = 0;
    } else {
      options.series[0] = count;
      options7.series[0] = countSubmited;
      optionsagm.series[0] = count;
      optionsagm.series[1] = countSubmited;
      optionsagm.series[2] = countSentBackCaseAlerts;
      optionsmonthlycm.series[0] = {
        name: "Pending",
        data: allocatedperdayData(options1.xaxis.categories, allocatedperday),
      };
      optionsmonthlycm.series[1] = {
        name: "sent",
        data: caseticketsperdayData(
          options1.xaxis.categories,
          caseticketsperday
        ),
      };
      // options7.series[1] = coutAcceptedNONSTR10;
    }
  }

  function dgmCount(
    count,
    approved_count,
    rejected_count,
    allocatedperday,
    DGMApprovedperDay,
    DGMRejectedperDay
  ) {
    if (count == undefined) {
      options10.series[0] = 0;
      options10.series[1] = 0;
      options10.series[2] = 0;
      optionsdgm.series = [];
      // options7.series[1] = 0;
    } else {
      options10.series[0] = count;
      options10.series[1] = approved_count;
      options10.series[2] = rejected_count;
      optionsdgm.series[0] = {
        name: "Pending",
        data: DgmallocatedperdayData(
          optionsdgm.xaxis.categories,
          allocatedperday
        ),
      };
      optionsdgm.series[1] = {
        name: "Approved",
        data: DGMApprovedperDayData(
          optionsdgm.xaxis.categories,
          DGMApprovedperDay
        ),
      };
      optionsdgm.series[2] = {
        name: "Rejected",
        data: DGMRejectedperDayData(
          optionsdgm.xaxis.categories,
          DGMRejectedperDay
        ),
      };
      // options7.series[1] = coutAcceptedNONSTR10;
    }
  }
  // offline dgm count

  function dgmofflineCount(
    count,
    approved,
    Rejected,
    assignedperdaydgm,
    DGMApprovedperDayoffline,
    DGMRejectedperDayoffline
  ) {
    if (count == undefined) {
      options15.series[0] = 0;
      options15.series[1] = 0;
      options15.series[2] = 0;
      optionsdgmoff.series = [];
    } else {
      options15.series[0] = count;
      options15.series[1] = approved;
      options15.series[2] = Rejected;
      optionsdgmoff.series[0] = {
        name: "Pending",
        data: DgmassignedperdayData(
          optionsdgmoff.xaxis.categories,
          assignedperdaydgm
        ),
      };
      optionsdgmoff.series[1] = {
        name: "Approved",
        data: DGMApprovedperDayofflineData(
          optionsdgmoff.xaxis.categories,
          DGMApprovedperDayoffline
        ),
      };
      optionsdgmoff.series[2] = {
        name: "Rejected",
        data: DGMRejectedperDayofflineData(
          optionsdgmoff.xaxis.categories,
          DGMRejectedperDayoffline
        ),
      };
    }
    console.log("ddddd", assignedperdaydgm);
  }

  // ros dashboard count
  function rosCount(count, countSubmited, assignedperday, submittedperday) {
    if (count == undefined) {
      optionsros.series[0] = 0;
      optionsros.series[1] = 0;
      optionsmonthlyros.series = [];
    } else {
      optionsros.series[0] = count;
      optionsros.series[1] = countSubmited;
      optionsmonthlyros.series[0] = {
        name: "Pending",
        data: assignedperdayDataOffline(
          options1.xaxis.categories,
          assignedperday
        ),
      };
      optionsmonthlyros.series[1] = {
        name: "sent",
        data: submittedperdayDataOffline(
          options1.xaxis.categories,
          submittedperday
        ),
      };
    }

    console.log(assignedperday);
    console.log(submittedperday);
  }

  ///////////   weekly dashboard     //////////////////////////

  // Function to generate date range dynamically
  function generateDateRange(numDays) {
    var dateArray = [];
    for (var i = numDays - 1; i >= 0; i--) {
      var currentDate = new Date();
      currentDate.setDate(currentDate.getDate() - i);

      // Format the date as "YYYY-MM-DD"
      var formattedDate = currentDate.toISOString().slice(0, 10);
      dateArray.push(formattedDate);
    }
    return dateArray;
  }

  // Function to generate "Pending" series data based on resultlist
  function generateSeriesData(dates, data) {
    const seriesData = Array(dates.length).fill(0);

    for (const entry of data) {
      const dateKey = Object.keys(entry)[0];
      const value = entry[dateKey];
      const dateIndex = dates.indexOf(dateKey);

      if (dateIndex !== -1) {
        seriesData[dateIndex] = value;
      }
    }

    return seriesData;
  }

  function generatePendingSeriesData(dates, resultlist) {
    return generateSeriesData(dates, resultlist);
  }

  function generateClosedSeriesData(dates, commentdata) {
    return generateSeriesData(dates, commentdata);
  }

  function generateSentSeriesData(dates, caseperday) {
    return generateSeriesData(dates, caseperday);
  }

  // Chart setup
  var options1 = {
    chart: {
      height: 380,
      type: "line",
      zoom: {
        enabled: false,
      },
      dropShadow: {
        enabled: false,
        top: 3,
        left: 2,
        blur: 4,
        opacity: 1,
      },
    },
    stroke: {
      curve: "smooth",
      width: 2,
    },
    colors: ["#00579C", "#C71007", "#098801"],
    series: [],
    title: {
      text: "Media",
      align: "left",
      offsetY: 25,
      offsetX: 20,
      style: {
        color: "#fff",
      },
    },
    markers: {
      size: 6,
      strokeWidth: 0,
      hover: {
        size: 9,
      },
    },
    grid: {
      show: true,
      padding: {
        bottom: 0,
      },
    },
    labels: [],
    xaxis: {
      tooltip: {
        enabled: false,
      },
      type: "datetime",
      categories: generateDateRange(8),
    },
    yaxis: {
      min: 0,
      forceNiceScale: true,
      labels: {
        formatter: function (value) {
          return Math.round(value);
        },
      },
    },
    legend: {
      position: "top",
      horizontalAlign: "right",
      offsetY: -20,
    },
  };

  // ###########  CM ###################
  function generateSeriesData(dates, dataList) {
    const seriesData = Array(dates.length).fill(0);

    for (const entry of dataList) {
      const dateKey = Object.keys(entry)[0];
      const value = entry[dateKey];
      const dateIndex = dates.indexOf(dateKey);

      if (dateIndex !== -1) {
        seriesData[dateIndex] = value;
      }
    }

    return seriesData;
  }

  function allocateresultlistData(dates, allocateresultlist) {
    return generateSeriesData(dates, allocateresultlist);
  }

  function caseresultlistData(dates, caseresultlist) {
    return generateSeriesData(dates, caseresultlist);
  }

  // ##########  AGM   ##################

  function generateSeriesData(dates, dataList) {
    const seriesData = Array(dates.length).fill(0);

    for (const entry of dataList) {
      const dateKey = Object.keys(entry)[0];
      const value = entry[dateKey];
      const dateIndex = dates.indexOf(dateKey);

      if (dateIndex !== -1) {
        seriesData[dateIndex] = value;
      }
    }

    return seriesData;
  }

  function allocatedperdayData(dates, allocatedperday) {
    return generateSeriesData(dates, allocatedperday);
  }

  function caseticketsperdayData(dates, caseticketsperday) {
    return generateSeriesData(dates, caseticketsperday);
  }

  // Chart setup
  var optionsmonthlycm = {
    chart: {
      height: 380,
      type: "line",
      zoom: {
        enabled: false,
      },
      dropShadow: {
        enabled: false,
        top: 3,
        left: 2,
        blur: 4,
        opacity: 1,
      },
    },
    stroke: {
      curve: "smooth",
      width: 2,
    },
    colors: ["#00579C", "#098801"],
    series: [],
    title: {
      text: "Media",
      align: "left",
      offsetY: 25,
      offsetX: 20,
      style: {
        color: "#fff",
      },
    },
    markers: {
      size: 6,
      strokeWidth: 0,
      hover: {
        size: 9,
      },
    },
    grid: {
      show: true,
      padding: {
        bottom: 0,
      },
    },
    labels: [],
    xaxis: {
      tooltip: {
        enabled: false,
      },
      type: "datetime",
      categories: generateDateRange(8),
    },
    yaxis: {
      min: 0,
      forceNiceScale: true,
      labels: {
        formatter: function (value) {
          return Math.round(value); // Rounds the value to the nearest integer
        },
      },
    },
    legend: {
      position: "top",
      horizontalAlign: "right",
      offsetY: -20,
    },
  };

  // ////// ####       DGM Dashboard                  ########  //////////

  // Function to generate "Pending" series data based on resultlist
  function generateSeriesData(dates, dataList) {
    const seriesData = Array(dates.length).fill(0);

    for (const entry of dataList) {
      const dateKey = Object.keys(entry)[0];
      const value = entry[dateKey];
      const dateIndex = dates.indexOf(dateKey);

      if (dateIndex !== -1) {
        seriesData[dateIndex] = value;
      }
    }

    return seriesData;
  }

  function DgmallocatedperdayData(dates, allocatedperday) {
    return generateSeriesData(dates, allocatedperday);
  }

  function DGMApprovedperDayData(dates, DGMApprovedperDay) {
    return generateSeriesData(dates, DGMApprovedperDay);
  }

  function DGMRejectedperDayData(dates, DGMRejectedperDay) {
    return generateSeriesData(dates, DGMRejectedperDay);
  }

  var optionsdgm = {
    chart: {
      height: 380,
      type: "line",
      zoom: {
        enabled: false,
      },
      dropShadow: {
        enabled: false,
        top: 3,
        left: 2,
        blur: 4,
        opacity: 1,
      },
    },
    stroke: {
      curve: "smooth",
      width: 2,
    },
    colors: ["#00579C", "#098801", "#C71007"],
    series: [],
    title: {
      text: "Media",
      align: "left",
      offsetY: 25,
      offsetX: 20,
      style: {
        color: "#fff",
      },
    },
    markers: {
      size: 6,
      strokeWidth: 0,
      hover: {
        size: 9,
      },
    },
    grid: {
      show: true,
      padding: {
        bottom: 0,
      },
    },
    labels: [],
    xaxis: {
      tooltip: {
        enabled: false,
      },
      type: "datetime",
      categories: generateDateRange(8),
    },
    yaxis: {
      min: 0,
      forceNiceScale: true,
      labels: {
        formatter: function (value) {
          return Math.round(value);
        },
      },
    },
    legend: {
      position: "top",
      horizontalAlign: "right",
      offsetY: -20,
    },
  };

  // //////  offline ros dashboard ///////////////////////////
  function generateSeriesDataOffline(dates, data) {
    const seriesData = Array(dates.length).fill(0);

    for (let i = 0; i < data.length; i++) {
      const commentEntry = data[i];
      const dateKey = Object.keys(commentEntry)[0];
      const value = commentEntry[dateKey];
      const dateIndex = dates.indexOf(dateKey);

      if (dateIndex !== -1) {
        seriesData[dateIndex] = value;
      }
    }

    return seriesData;
  }

  function assignedperdayDataOffline(dates, assignedperday) {
    return generateSeriesDataOffline(dates, assignedperday);
  }

  function submittedperdayDataOffline(dates, submittedperday) {
    return generateSeriesDataOffline(dates, submittedperday);
  }

  function assignedperdayDataOfflineagm(dates, assignedperdayagm) {
    return generateSeriesDataOffline(dates, assignedperdayagm);
  }

  function submittedperdayDataOfflineagm(dates, submittedperdayagm) {
    return generateSeriesDataOffline(dates, submittedperdayagm);
  }

  // ///////////////////////////////////

  var optionsmonthlyros = {
    chart: {
      height: 380,
      type: "line",
      zoom: {
        enabled: false,
      },
      dropShadow: {
        enabled: false,
        top: 3,
        left: 2,
        blur: 4,
        opacity: 1,
      },
    },
    stroke: {
      curve: "smooth",
      width: 2,
    },
    colors: ["#00579C", "#098801"],
    series: [],
    title: {
      text: "Media",
      align: "left",
      offsetY: 25,
      offsetX: 20,
      style: {
        color: "#fff",
      },
    },
    markers: {
      size: 6,
      strokeWidth: 0,
      hover: {
        size: 9,
      },
    },
    grid: {
      show: true,
      padding: {
        bottom: 0,
      },
    },
    labels: [],
    xaxis: {
      tooltip: {
        enabled: false,
      },
      type: "datetime",
      categories: generateDateRange(8),
    },
    legend: {
      position: "top",
      horizontalAlign: "right",
      offsetY: -20,
    },
  };

  // //////   dgm offline dashboard   ////////////////////
  function DgmassignedperdayData(dates, assignedperdaydgm) {
    const dgmassignedData = [];

    // Initialize pendingData array with zeros
    for (let i = 0; i < dates.length; i++) {
      dgmassignedData.push(0);
    }

    // Update pendingData based on resultlist
    for (let i = 0; i < assignedperdaydgm.length; i++) {
      const commentEntry = assignedperdaydgm[i];
      const dateKey = Object.keys(commentEntry)[0];
      const value = commentEntry[dateKey];
      const dateIndex = dates.indexOf(dateKey);

      if (dateIndex !== -1) {
        // Date found in the graph x-axis, update "Pending" series data
        dgmassignedData[dateIndex] = value;
      }
    }

    return dgmassignedData;
  }
  //   approved
  function DGMApprovedperDayofflineData(dates, DGMApprovedperDayoffline) {
    const DGMApprovedoffline = [];

    // Initialize pendingData array with zeros
    for (let i = 0; i < dates.length; i++) {
      DGMApprovedoffline.push(0);
    }

    // Update pendingData based on resultlist
    for (let i = 0; i < DGMApprovedperDayoffline.length; i++) {
      const commentEntry = DGMApprovedperDayoffline[i];
      const dateKey = Object.keys(commentEntry)[0];
      const value = commentEntry[dateKey];
      const dateIndex = dates.indexOf(dateKey);

      if (dateIndex !== -1) {
        // Date found in the graph x-axis, update "Pending" series data
        DGMApprovedoffline[dateIndex] = value;
      }
    }

    return DGMApprovedoffline;
  }

  //  rejected

  function DGMRejectedperDayofflineData(dates, DGMRejectedperDayoffline) {
    const DGMRejectedoffline = [];

    // Initialize pendingData array with zeros
    for (let i = 0; i < dates.length; i++) {
      DGMRejectedoffline.push(0);
    }

    // Update pendingData based on resultlist
    for (let i = 0; i < DGMRejectedperDayoffline.length; i++) {
      const commentEntry = DGMRejectedperDayoffline[i];
      const dateKey = Object.keys(commentEntry)[0];
      const value = commentEntry[dateKey];
      const dateIndex = dates.indexOf(dateKey);

      if (dateIndex !== -1) {
        // Date found in the graph x-axis, update "Pending" series data
        DGMRejectedoffline[dateIndex] = value;
      }
    }

    return DGMRejectedoffline;
  }

  var optionsdgmoff = {
    chart: {
      height: 380,
      type: "line",
      zoom: {
        enabled: false,
      },
      dropShadow: {
        enabled: false,
        top: 3,
        left: 2,
        blur: 4,
        opacity: 1,
      },
    },
    stroke: {
      curve: "smooth",
      width: 2,
    },
    colors: ["#00579C", "#098801", "#C71007"],
    series: [],
    title: {
      text: "Media",
      align: "left",
      offsetY: 25,
      offsetX: 20,
      style: {
        color: "#fff",
      },
    },
    markers: {
      size: 6,
      strokeWidth: 0,
      hover: {
        size: 9,
      },
    },
    grid: {
      show: true,
      padding: {
        bottom: 0,
      },
    },
    labels: [],
    xaxis: {
      tooltip: {
        enabled: false,
      },
      type: "datetime",
      categories: generateDateRange(8),
    },
    legend: {
      position: "top",
      horizontalAlign: "right",
      offsetY: -20,
    },
  };
  // it dashboard  monthly /////////////

  function itperdayDatamonthly(dates, perdayDatait) {
    const itperdayData = [];

    // Initialize pendingData array with zeros
    for (let i = 0; i < dates.length; i++) {
      itperdayData.push(0);
    }

    // Update pendingData based on resultlist
    for (let i = 0; i < perdayDatait.length; i++) {
      const commentEntry = perdayDatait[i];
      const dateKey = Object.keys(commentEntry)[0];
      const value = commentEntry[dateKey];
      const dateIndex = dates.indexOf(dateKey);

      if (dateIndex !== -1) {
        // Date found in the graph x-axis, update "Pending" series data
        itperdayData[dateIndex] = value;
      }
    }

    return itperdayData;
  }

  var optionsmonthlyit = {
    chart: {
      height: 380,
      type: "line",
      zoom: {
        enabled: false,
      },
      dropShadow: {
        enabled: false,
        top: 3,
        left: 2,
        blur: 4,
        opacity: 1,
      },
    },
    stroke: {
      curve: "smooth",
      width: 2,
    },
    colors: ["#00579C"],
    series: [],
    title: {
      text: "Media",
      align: "left",
      offsetY: 25,
      offsetX: 20,
      style: {
        color: "#fff",
      },
    },
    markers: {
      size: 6,
      strokeWidth: 0,
      hover: {
        size: 9,
      },
    },
    grid: {
      show: true,
      padding: {
        bottom: 0,
      },
    },
    labels: [],
    xaxis: {
      tooltip: {
        enabled: false,
      },
      type: "datetime",
      categories: generateDateRange(8),
    },
    legend: {
      position: "top",
      horizontalAlign: "right",
      offsetY: -20,
    },
  };

  //////////     weekly dashboard   ///////////////////////////

  var options = {
    chart: {
      type: "donut",
      width: 380,
    },
    colors: ["#00579c"],
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
    series: [],
    labels: ["Total Cases"],
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

  // Submited data to higher level offercer

  var options8 = {
    chart: {
      type: "donut",
      width: 380,
    },
    colors: ["#00579c"],
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
      onItemHover: {
        highlightDataSeries: true,
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
    series: [],
    labels: ["Total Cases"],
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

  // alert raised in a day && send to next officer start option 2  start
  var options2 = {
    chart: {
      type: "donut",
      width: 380,
    },
    colors: ["#00529C", "#FF4560"],
    dataLabels: {
      enabled: false,
    },
    legend: {
      position: "bottom",
      horizontalAlign: "center",
      fontSize: "17px",
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
          size: "75%",
          background: "transparent",
          labels: {
            show: true,
            name: {
              show: true,
              fontSize: "22px",
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
      width: 2,
    },
    series: [3000, 2000],
    labels: ["Aproved", "Rejected"],
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
                size: "75%",
              },
            },
          },
        },
      },
    ],
  };
  //  alert raised in a day && send to next officer end option 2 end

  // MLRO Alerts  chart-5 option5 start

  var optionsmlro = {
    chart: {
      type: "donut",
      width: 380,
    },
    colors: ["#00579c", "#098801", "#c71007", "#52788b"],
    dataLabels: {
      enabled: false,
    },
    legend: {
      position: "bottom",
      horizontalAlign: "center",
      fontSize: "17px",
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
          size: "70%",
          background: "transparent",
          labels: {
            show: true,
            name: {
              show: true,
              fontSize: "22px",
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
      width: 2,
    },
    series: [],
    labels: ["Total Cases", "Sent Cases", "Closed Cases", "Reallocated Cases"],
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
                size: "75%",
              },
            },
          },
        },
      },
    ],
  };

  var options5 = {
    chart: {
      type: "donut",
      width: 380,
    },
    colors: ["#00529C", "#FF4560"],
    dataLabels: {
      enabled: false,
    },
    legend: {
      position: "bottom",
      horizontalAlign: "center",
      fontSize: "17px",
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
          size: "75%",
          background: "transparent",
          labels: {
            show: true,
            name: {
              show: true,
              fontSize: "22px",
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
      width: 2,
    },
    series: [],
    labels: ["Aproved", "Rejected"],
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
                size: "75%",
              },
            },
          },
        },
      },
    ],
  };

  // MLRO Alerts  chart-5 options5 end

  // CM/SM Alerts  chart-6 options6 start
  var optionscm = {
    chart: {
      type: "donut",
      width: 380,
    },
    colors: ["#00579c", "#098801", "#c71007", "#52788b"],
    dataLabels: {
      enabled: false,
    },
    legend: {
      position: "bottom",
      horizontalAlign: "center",
      fontSize: "17px",
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
          size: "75%",
          background: "transparent",
          labels: {
            show: true,
            name: {
              show: true,
              fontSize: "22px",
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
      width: 2,
    },
    series: [],
    labels: ["Total Cases", "Sent Cases", "Closed Cases", "Reallocated Cases"],
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
                size: "75%",
              },
            },
          },
        },
      },
    ],
  };

  var options6 = {
    chart: {
      type: "donut",
      width: 380,
    },
    colors: ["#00529C", "#FF4560"],
    dataLabels: {
      enabled: false,
    },
    legend: {
      position: "bottom",
      horizontalAlign: "center",
      fontSize: "17px",
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
          size: "75%",
          background: "transparent",
          labels: {
            show: true,
            name: {
              show: true,
              fontSize: "22px",
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
      width: 2,
    },
    series: [],
    labels: ["Aproved", "Rejected"],
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
                size: "75%",
              },
            },
          },
        },
      },
    ],
  };
  // CM/SM Alerts  chart-6 options6 end

  // Alert from AGM Start

  var optionsagm = {
    chart: {
      type: "donut",
      width: 380,
    },
    colors: ["#00579c", "#098801", "#52788b"],
    dataLabels: {
      enabled: false,
    },
    legend: {
      position: "bottom",
      horizontalAlign: "center",
      fontSize: "17px",
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
          size: "75%",
          background: "transparent",
          labels: {
            show: true,
            name: {
              show: true,
              fontSize: "22px",
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
      width: 2,
    },
    series: [],
    labels: ["Total Cases", "Sent Cases", "Reallocated Cases"],
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
                size: "75%",
              },
            },
          },
        },
      },
    ],
  };

  var options7 = {
    chart: {
      type: "donut",
      width: 380,
    },
    colors: ["#00529C", "#FF4560"],
    dataLabels: {
      enabled: false,
    },
    legend: {
      position: "bottom",
      horizontalAlign: "center",
      fontSize: "17px",
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
          size: "75%",
          background: "transparent",
          labels: {
            show: true,
            name: {
              show: true,
              fontSize: "22px",
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
      width: 2,
    },
    series: [],
    labels: ["Aproved", "Rejected"],
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
                size: "75%",
              },
            },
          },
        },
      },
    ],
  };
  // Alert from  AGM End

  // alerts of dgm
  var options10 = {
    chart: {
      type: "donut",
      width: 380,
    },
    colors: ["#00579c", "#098801", "#c71007"],
    dataLabels: {
      enabled: false,
    },
    legend: {
      position: "bottom",
      horizontalAlign: "center",
      fontSize: "17px",
      markers: {
        width: 10,
        height: 10,
      },
      itemMargin: {
        horizontal: 0,
        vertical: 8,
      },
      onItemClick: {
        toggleDataSeries: true,
      },
      onItemHover: {
        highlightDataSeries: true,
      },
    },
    plotOptions: {
      pie: {
        donut: {
          size: "75%",
          background: "transparent",
          labels: {
            show: true,
            name: {
              show: true,
              fontSize: "22px",
              fontFamily: "Nunito, sans-serif",
              color: undefined,
              offsetY: -10,
            },
            value: {
              show: true,
              fontSize: "26px",
              fontFamily: "Nunito, sans-serif",
              color: "#202020", // Corrected color code
              offsetY: 16,
              formatter: function (val) {
                return val;
              },
            },
            total: {
              show: true,
              showAlways: true,
              showLegend: false,
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
      width: 2,
    },
    series: [],
    labels: ["Total Cases", "Approved", "Rejected"],
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
      },
      {
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
                size: "75%",
              },
            },
          },
        },
      },
    ],
  };

  var options11 = {
    chart: {
      type: "donut",
      width: 380,
    },
    colors: ["#00529C", "#FF4560"],
    dataLabels: {
      enabled: false,
    },
    legend: {
      position: "bottom",
      horizontalAlign: "center",
      fontSize: "17px",
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
          size: "75%",
          background: "transparent",
          labels: {
            show: true,
            name: {
              show: true,
              fontSize: "22px",
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
      width: 2,
    },
    series: [],
    labels: ["Aproved", "Rejected"],
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
                size: "75%",
              },
            },
          },
        },
      },
    ],
  };

  // dgm alerts grpah
  var options4 = {
    chart: {
      type: "donut",
      width: 380,
    },
    colors: ["#006be7", "#e2a03f", "#e7515a"],
    dataLabels: {
      enabled: false,
    },
    legend: {
      position: "bottom",
      horizontalAlign: "center",
      fontSize: "17px",
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
          size: "75%",
          background: "transparent",
          labels: {
            show: true,
            name: {
              show: true,
              fontSize: "22px",
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
      width: 2,
    },
    series: [1200, 1000, 2200],
    labels: ["Aproved", "Pending", "Rejected"],
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
                size: "75%",
              },
            },
          },
        },
      },
    ],
  };

  // cm page mlro pending alert
  var options9 = {
    series: [],
    chart: {
      width: 380,
      type: "pie",
    },
    labels: [],
    responsive: [
      {
        breakpoint: 480,
        options: {
          chart: {
            width: 200,
          },
          legend: {},
          position: "bottom",
        },
      },
    ],
    plotOptions: {
      pie: {
        customScale: 0.8, // You can adjust this value as needed
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
                return w.globals.series.reduce(function (a, b) {
                  return a + b;
                }, 0);
              },
            },
          },
        },
      },
    },
  };

  // Example usage
  // agm offline dashboard graph chart
  var options12 = {
    chart: {
      type: "donut",
      width: 380,
    },
    colors: ["#00579c", "#098801"],
    dataLabels: {
      enabled: false,
    },
    legend: {
      position: "bottom",
      horizontalAlign: "center",
      fontSize: "17px",
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
          size: "75%",
          background: "transparent",
          labels: {
            show: true,
            name: {
              show: true,
              fontSize: "22px",
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
      width: 2,
    },
    series: [],
    labels: ["Total Cases", "Sent Cases"],
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
                size: "75%",
              },
            },
          },
        },
      },
    ],
  };

  // ros dashboard
  var options13 = {
    chart: {
      type: "donut",
      width: 380,
    },
    colors: ["#00579c"],
    dataLabels: {
      enabled: false,
    },
    legend: {
      position: "bottom",
      horizontalAlign: "center",
      fontSize: "17px",
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
          size: "75%",
          background: "transparent",
          labels: {
            show: true,
            name: {
              show: true,
              fontSize: "22px",
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
      width: 2,
    },
    series: [],
    labels: ["Total Cases"],
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
                size: "75%",
              },
            },
          },
        },
      },
    ],
  };

  //  dgm offliine dashboard

  var options14 = {
    chart: {
      type: "donut",
      width: 380,
    },
    colors: ["#00579c"],
    dataLabels: {
      enabled: false,
    },
    legend: {
      position: "bottom",
      horizontalAlign: "center",
      fontSize: "17px",
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
          size: "75%",
          background: "transparent",
          labels: {
            show: true,
            name: {
              show: true,
              fontSize: "22px",
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
      width: 2,
    },
    series: [],
    labels: ["Total Cases"],
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
                size: "75%",
              },
            },
          },
        },
      },
    ],
  };

  var options15 = {
    chart: {
      type: "donut",
      width: 380,
    },
    colors: ["#00579c", "#098801", "#c71007"],
    dataLabels: {
      enabled: false,
    },
    legend: {
      position: "bottom",
      horizontalAlign: "center",
      fontSize: "17px",
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
          size: "75%",
          background: "transparent",
          labels: {
            show: true,
            name: {
              show: true,
              fontSize: "22px",
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
      width: 2,
    },
    series: [],
    labels: ["Total Cases", "Aproved", "Rejected"],
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
                size: "75%",
              },
            },
          },
        },
      },
    ],
  };

  var options16 = {
    chart: {
      type: "donut",
      width: 380,
    },
    colors: ["#00529C", "#FF4560"],
    dataLabels: {
      enabled: false,
    },
    legend: {
      position: "bottom",
      horizontalAlign: "center",
      fontSize: "17px",
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
          size: "75%",
          background: "transparent",
          labels: {
            show: true,
            name: {
              show: true,
              fontSize: "22px",
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
              color: "#888EA8",
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
      width: 2,
    },
    series: [],
    labels: ["Aproved", "Rejected"],
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
                size: "75%",
              },
            },
          },
        },
      },
    ],
  };

  // ###  ros dashboard

  var optionsros = {
    chart: {
      type: "donut",
      width: 380,
    },
    colors: ["#00579c", "#098801"],
    dataLabels: {
      enabled: false,
    },
    legend: {
      position: "bottom",
      horizontalAlign: "center",
      fontSize: "17px",
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
          size: "75%",
          background: "transparent",
          labels: {
            show: true,
            name: {
              show: true,
              fontSize: "22px",
              fontFamily: "Nunito, sans-serif",
              color: undefined,
              offsetY: -10,
            },
            value: {
              show: true,
              fontSize: "25px",
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
      width: 10,
    },
    series: [],
    labels: ["Total Cases", "Sent Cases"],
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
                size: "75%",
              },
            },
          },
        },
      },
    ],
  };

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
  var d_2C_1 = new ApexCharts(
    document.querySelector("#daily-sales"),
    d_2options1
  );
  d_2C_1.render();

  /*
    ============================
        Total Orders | Render
    ============================
*/
  var d_2C_2 = new ApexCharts(
    document.querySelector("#total-orders"),
    d_2options2
  );
  d_2C_2.render();

  /*
    ================================
        Revenue Monthly | Render
    ================================
*/

  var chartitmonthly = new ApexCharts(
    document.querySelector("#revenueMonthlyit"),
    optionsmonthlyit
  );

  chartitmonthly.render();

  var chart1 = new ApexCharts(
    document.querySelector("#revenueMonthly"),
    options1
  );

  chart1.render();

  var chartmonthlycm = new ApexCharts(
    document.querySelector("#revenueMonthlycm"),
    optionsmonthlycm
  );

  chartmonthlycm.render();

  var chartdgm = new ApexCharts(
    document.querySelector("#revenueMonthlydgm"),
    optionsdgm
  );
  chartdgm.render();

  var chartmonthlyros = new ApexCharts(
    document.querySelector("#revenueMonthlyros"),
    optionsmonthlyros
  );

  chartmonthlyros.render();

  var chartdgmoff = new ApexCharts(
    document.querySelector("#revenueMonthlydgmoff"),
    optionsdgmoff
  );
  chartdgmoff.render();

  /*
    =================================
        Sales By Category | Render
    =================================
*/
  var chartit = new ApexCharts(document.querySelector("#chartit-2"), options);

  chartit.render();

  var chartmlro = new ApexCharts(
    document.querySelector("#chartmlro-1"),
    optionsmlro
  );

  chartmlro.render();

  var chartcm = new ApexCharts(document.querySelector("#chartcm-1"), optionscm);

  chartcm.render();

  var chartagm = new ApexCharts(
    document.querySelector("#chartagm-1"),
    optionsagm
  );

  chartagm.render();

  var chartit = new ApexCharts(document.querySelector("#chartit-3"), options8);

  chartit.render();

  var chart = new ApexCharts(document.querySelector("#chart-2"), options2);

  chart.render();

  var chart3 = new ApexCharts(document.querySelector("#chart-3"), options2);

  chart3.render();

  var chart5 = new ApexCharts(document.querySelector("#chart-5"), options5);

  chart5.render();

  var chart6 = new ApexCharts(document.querySelector("#chart-6"), options6);

  chart6.render();

  var chart7 = new ApexCharts(document.querySelector("#chart-7"), options7);

  chart7.render();

  var chartcms = new ApexCharts(document.querySelector("#chartcm"), options9);
  chartcms.render();

  var chart10 = new ApexCharts(document.querySelector("#chart-10"), options10);

  chart10.render();

  var chart11 = new ApexCharts(document.querySelector("#chart-11"), options16);

  chart11.render();

  var chartros = new ApexCharts(
    document.querySelector("#chartros-1"),
    optionsros
  );
  var chartros1 = new ApexCharts(
    document.querySelector("#chartros-2"),
    options11
  );
  chartros.render();
  chartros1.render();
  var chartagmoffline = new ApexCharts(
    document.querySelector("#chartagmoffline_1"),
    options12
  );
  var chartagmoffline1 = new ApexCharts(
    document.querySelector("#chartagmoffline-2"),
    options11
  );
  chartagmoffline.render();
  chartagmoffline1.render();

  var chart13 = new ApexCharts(document.querySelector("#chart-13"), options13);

  chart13.render();

  var chart14 = new ApexCharts(document.querySelector("#chart-14"), options14);

  chart14.render();

  var chart15 = new ApexCharts(document.querySelector("#chart-15"), options15);
  chart15.render();

  /*
    =============================================
        Perfect Scrollbar | Recent Activities
    =============================================
*/
  const ps = new PerfectScrollbar(document.querySelector(".mt-container"));
} catch (e) {
  console.log(e);
}

/**
 * =========================================================
 * Alerts charts in alertsOpeeation.html file on line : 1687
 * =========================================================
 */

// var optionsC = {
//   colors:["#14cfb9","#ff5b6b"],
//   series: [{
//   name: 'Aproved',
//   data: [31, 40, 28, 51, 42, 109, 100, 96, 85, 70, 90]
// }, {
//   name: 'Rejected',
//   data: [11, 32, 45, 32, 34, 52, 41, 74, 68, 81, 108]
// }],
//   chart: {
//     width:400,
//   height: 150,
//   type: 'area',
// },
// dataLabels: {
//   enabled: false,
// },
// stroke: {
//   curve: 'smooth'
// },
// xaxis: {
//   type: 'datetime',
//   categories: ["2018-09-19T00:00:00.000Z", "2018-09-19T01:30:00.000Z", "2018-09-19T02:30:00.000Z", "2018-09-19T03:30:00.000Z", "2018-09-19T04:30:00.000Z", "2018-09-19T05:30:00.000Z", "2018-09-19T06:30:00.000Z", "2018-09-19T07:30:00.000Z", "2018-09-19T08:30:00.000Z", "2018-09-19T09:30:00.000Z", "2018-09-19T10:30:00.000Z"],
//   labels: {
//     style: {
//       fontSize: '6px', // You can change the font size here
//       marginBottom: '20px'
//     }
//   }
// },
// yaxis: {
//   labels: {
//     style: {
//       fontSize: '6px' // You can change the font size here
//     }
//   }
// },
// tooltip: {
//   x: {
//     format: 'dd/MM/yy HH:mm'
//   },
// },
// };

// var chartC = new ApexCharts(document.querySelector("#alertsChartTimes"), optionsC);
// chartC.render();
