function [] = plotHandshake(opt) 

% Common variables 
folder = '/home/varvello/WorkTelefonica/HTTP-2/results'; 
figFolder = './fig';
kind_line = ['m';'b';'g';'m';'b';'g';'m';'b';'g';'m';'o';':';'d';'+';'<';'s';'.';'-';'g';'p'];
line_style = ['-';';';':'];
N_slices=1;

% Close figures 
close all 

% Plotting protocol usage evolution over time
protocol = [
	'fwd'
	'ssl'
	'spp'
	]; 
	%'spp_mod'
	%]; 
% Plotting protocol usage evolution over time
leg= [
	'TLS (forwarding)'
	'TLS (splitting) '
	'SPP             '
	]; 
	%'SPP (modified)  '
	%]; 

nProt = size(protocol, 1); 
handshakeTime = figure(); 
hold on 

% Load data to plot from files 
counter = 1;
if (opt == 2) 
	suffix = 'timeFirstByte_slice'; 
end
if (opt == 3) 
	suffix = 'timeFirstByte_latency'; 
end
if (opt == 4) 
	suffix = 'timeFirstByte_proxy'; 
end


% Main loop 
for ii = 1 : nProt
	currProt = strtrim(protocol(ii, :)); 
	file = sprintf('res_%s_%s', currProt, suffix); 
	data = dlmread(file); 
	h = errorbar(data(:, 4).*1000, data(:, 5).*1000); 
	%h = errorbar(X', data(:, 4).*1000, data(:, 5).*1000); 
	if (ii > 3) 
		set (h, 'color', kind_line(counter), 'LineWidth', 3, 'LineStyle', '--');
	else 
		set (h, 'color', kind_line(counter), 'LineWidth', 3);
	end
	%if (ii == 1)
	%	leg = {sprintf('%s',currProt)};
	%else
	%	leg = [leg, {sprintf('%s', currProt)}];
	%end
	counter = counter + 1; 
	if (opt == 2) 
		rtt = data(1, 2); 
		N = data(1, 3); 
	end
	if (opt == 3)
		N_slices = data(1, 2);
		N = data(1, 3); 
	end
	if (opt == 4)
		N_slices = data(1, 2);
		rtt = data(1, 3); 
	end
end

% Add figure details 
if (opt == 2) 
	xlabel('No. slices (#)');
end
if (opt == 3) 
	xlabel('Network Latency (ms)');
end
if (opt == 4) 
	xlabel('No. proxies (#)');
end

ylabel('Time to First Byte (ms)');
legend(leg, 'Location', 'NorthWest');
grid on 
set(0,'defaultaxesfontsize',18);
if (opt == 2) 
	t = sprintf('Latency=%dms ; N_{prxy}=%d', rtt, N); 
end
if (opt == 3) 
	t = sprintf('S=%d ; N_{prxy}=%d', N_slices, N); 
end
if (opt == 4) 
	t = sprintf('S=%d ; Latency=%dms', N_slices, rtt); 
end
title(t);

% set xtick label correctly 
xlim([1 size(data, 1)]); 
X = 1:size(data, 1); 
set(gca, 'XTick', X, 'XTickLabel', data(:, 1)'); 
%set(gca, 'XTickLabel', [5; 10; 20]); 
%if (opt == 3) 
%	set(gca, 'YScale','log'); 
%end
if (opt == 2) 
	outFile = sprintf ('%s/time_1st_byte_slice.eps', figFolder); 
end
if (opt == 3) 
	outFile = sprintf ('%s/time_1st_byte_latency.eps', figFolder); 
end
if (opt == 4) 
	outFile = sprintf ('%s/time_1st_byte_proxy.eps', figFolder); 
end
saveas (h, outFile, 'psc2');

