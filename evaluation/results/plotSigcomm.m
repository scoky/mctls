% function to plot several statistics for the Sigcomm paper 
% opt - graph type 
% remote   - local or remote experiment
% parallel - if = 1 it refers to experiment ran on multiple machines at the same time
% role     - required by option 7 to indicate whether we wannt plot for "client", "server" or "mbox"

function [] = plotHandshake(opt, remote, parallel, role) 

% Common variables 
folder = '/home/varvello/WorkTelefonica/HTTP-2/sigcomm_evaluation/secure_proxy_protocol/evaluation/results/tmp'; 
%folder = '/home/varvello/WorkTelefonica/HTTP-2/sigcomm_evaluation/secure_proxy_protocol/evaluation/results'; 
figFolder = './fig/matlab';
kind_line = ['m';'b';'g';'m';'b';'g';'m';'b';'g';'m';'o';':';'d';'+';'<';'s';'.';'-';'g';'p'];
line_style = ['-';';';':'];
N_slices=1;
rate=20; % temporary rate used for file download
% Close figures 
close all 

% Protocol  and protocol labels 
protocol = [
	'spp'
	'fwd'
	'ssl'
	%'pln'
	]; 
protoLabel = [
	'SPP             '
	'TLS (forwarding)'
	'TLS (splitting) '
	%'PLN             '
	]; 

% machines and label and hardware 
machines  = [
	%'54.76.148.166    '	
	%'54.67.37.251     '
	%'tid.system-ns.net'
	'localhost        '
	]; 

machinesLabel  = [
	%'Amazon-1'	
	%'Amazon-2'	
	%'TID     '
	'Laptop  '
	]; 

machinesHardware = [
	%'Amazon1 E5(1-core -2.50GHz) 2GB   '
	%'Amazon2 E5(1-core - 2.50GHz) 2GB  '
	%'TID i7(7-cores - 3.40GHz) 16GB    '
	'Laptop i5(4-cores - 2.50GHz) 4GB  '
	]; 

nProt = size(protocol, 1); 
nMachines = size(machines, 1); 

if (opt == 1) 
	h = figure(); 
	a = dlmread('number_tls');
	l = cdfplot(a);                   
	set (l, 'color', kind_line(1), 'LineWidth', 3); 
	hold on; 
	x1 = 10; 
	y1 = get(gca,'ylim'); 
	hold on
	l1 = plot([x1 x1], y1); 
	set (l1, 'color', kind_line(2), 'LineWidth', 3, 'LineStyle', '--');
	xlabel('Number of connections (#)');
	ylabel('CDF (0-1)');
	title('Alexa TOP 500');
	outFile = sprintf ('%s/cdf_tls.eps', figFolder) 
	saveas (h, outFile, 'psc2');
	error('done, check plot'); 
end 

if (parallel == 0) 
	nMachines = 1 
end 

% File naming according to options
if (opt == 2) 
	if (remote == 0) 
		suffix = 'timeFirstByte_slice'; 
	else
		suffix = 'remote_timeFirstByte_slice'; 
	end	
end
if (opt == 3) 
	suffix = 'timeFirstByte_latency'; 
end
if (opt == 4) 
	suffix = 'timeFirstByte_proxy'; 
end
if (opt == 5) 
	suffix = 'downloadTime'; 
end
if (opt == 6) 
	suffix = 'downloadTime_browser'; 
end
if (opt == 7) 
	suffix = 'connections_slice'; 
	if (parallel == 1) 
		comparison = figure(); 
	end
end


% Main loop 
counter2 = 1
for jj = 1 : nMachines
	% figure handler 
	fig_handler(jj) = figure(); 
	hold on 
	if (parallel == 1) 
		currMachine = strtrim(machines(jj, :)); 
		currMachineLabel = strtrim(machinesLabel(jj, :)); 
		currMachineHardware = strtrim(machinesHardware(jj, :)); 
	end
	counter = 1;
	for ii = 1 : nProt
		figure(fig_handler(jj)); 
		currProt = strtrim(protocol(ii, :)); 
		currProtLabel = strtrim(protoLabel(ii, :)); 
		if (parallel == 0) 
			file = sprintf('%s/res_%s_%s', folder, currProt, suffix) 
		else 
			file = sprintf('%s/res_%s_%s_%s_%s', folder, currProt, suffix, role, currMachine) 
		end
		if exist(file, 'file') ~= 2
			continue
		end
		data = dlmread(file); 
		
		if (opt < 5) 
			h = errorbar(data(:, 4).*1000, data(:, 5).*1000); 
		elseif (opt == 5) 
				h = errorbar(data(:, 4), data(:, 5)); 
		elseif (opt == 6) 
				h = cdfplot(data(:, 4)); 
				% h1 = cdfplot(data(:, 5)); % here we can plot CDF of stdev...
		elseif (opt == 7) 
				h = errorbar(data(:, 4), data(:, 5)); 
		end
		if (ii > 3) 
			set (h, 'color', kind_line(counter), 'LineWidth', 3, 'LineStyle', '--');
		else 
			set (h, 'color', kind_line(counter), 'LineWidth', 3);
		end
		if (jj == 1)
			if (counter == 1)
				leg = {sprintf('%s',currProtLabel)};
			else
				leg = [leg, {sprintf('%s', currProtLabel)}];
			end
		end
		% plot only one though all are available
		if (remote == 1 & ii == 1)  
			h_ping = errorbar(data(:, 6), data(:, 7)); 
			set (h_ping, 'color', 'r', 'LineWidth', 3);
			leg = [leg, {sprintf('Measured RTT')}];
		end 
		counter = counter + 1; 
		if (opt == 2 || opt == 7) 
			rtt = data(1, 2); 
			N = data(1, 3); 
		end
		if (opt == 3)
			N_slices = data(1, 2);
			N = data(1, 3); 
		end
		if (opt == 4 || opt == 5 || opt == 6)
			N_slices = data(1, 2);
			rtt = data(1, 3); 
		end
		% HERE
		if (currProt == 'spp' & parallel == 1)
			figure(comparison)
			h_comp = errorbar(data(:, 4), data(:, 5)); 
			hold on
			if (jj > 3) 
				set (h_comp, 'color', kind_line(counter2), 'LineWidth', 3, 'LineStyle', '--');
			else 
				set (h_comp, 'color', kind_line(counter2), 'LineWidth', 3);
			end
			counter2 = counter2 + 1; 
			if (jj == 1)
				leg_comparison = {sprintf('%s', currMachineLabel)};
				% TOFIX set xtick label correctly 
				xlim([1 size(data, 1)]); 
				X = 1:size(data, 1); 
				set(gca, 'XTick', X, 'XTickLabel', data(:, 1)'); 
			else
				leg_comparison = [leg_comparison, {sprintf('%s', currMachineLabel)}];
			end
		end
	end

	% make sure we work on right figure
	figure(fig_handler(jj)); 

	% X axis labels
	if (opt == 2 || opt == 7) 
		xlabel('No. slices (#)');
	end
	if (opt == 3) 
		xlabel('Network Latency (ms)');
	end
	if (opt == 4) 
		xlabel('No. proxies (#)');
	end
	if (opt == 5) 
		xlabel('File size (KB)');
	end
	if (opt == 6) 
		xlabel('Download Time (ms)');
	end
	% Y axis labels
	if (opt < 5) 
		ylabel('Time to First Byte (ms)');
	elseif (opt == 5) 
		ylabel('Download Time (sec)');
	elseif (opt == 6) 
		ylabel('CDF (0-1)');
	elseif (opt == 7) 
		ylabel('Connection per second (cps)');
	end

	% More plot details 
	if (parallel == 0) 
		legend(leg, 'Location', 'NorthWest');
	else 
		%legend(leg, 'Location', 'SouthEast');
		legend(leg, 'Location', 'NorthWest');
		%legend(leg, 'Location', 'North'); 
	end
	grid on 
	set(0,'defaultaxesfontsize',18);

	% derive title based on input 
	if (opt == 2)
		if (remote == 0)  
			t = sprintf('Latency=%dms ; N_{prxy}=%d ; LOCAL', rtt, N); 
		else
			t = sprintf('N_{prxy}=%d ; C(LAPTOP)->MBOX(AMAZON)->S(AMAZON)',  N); 
		end
	end
	if (opt == 3) 
		if (remote == 0)  
			t = sprintf('S=%d ; N_{prxy}=%d ; LOCAL', N_slices, N); 
		end
	end
	if (opt == 4)
		if (remote == 0)  
			t = sprintf('S=%d ; Latency=%dms ; LOCAL', N_slices, rtt); 
		end
	end
	if (opt == 5) 
		if (remote == 0)  
			t = sprintf('S=%d ; Latency=%dms; Rate=%dMbps ; LOCAL', N_slices, rtt, rate); 
		end
	end
	if (opt == 6) 
		if (remote == 0)  
			t = sprintf('S=%d ; Latency=%dms ; LOCAL', N_slices, rtt); 
		else
			t = sprintf('S=%d ; AMAZON', N_slices, rtt); 
		end
	end
	if (opt == 7) 
		if (parallel == 0)  
			t = sprintf('Latency=%dms ; N_{prxy}=%d ; LOCAL', rtt, N); 
		else
			t = sprintf('Latency=%dms ; N_{prxy}=%d ; %s ; %s', rtt, N, currMachineHardware, role); 
		end
	end

	% set title
	title(t);

	% set xtick label correctly 
	xlim([1 size(data, 1)]); 
	X = 1:size(data, 1); 
	set(gca, 'XTick', X, 'XTickLabel', data(:, 1)'); 

	% set log scale 
	%if (opt == 7 & parallel == 1) 
	%	set(gca, 'YScale','log'); 
	%end
	if (opt == 2)
		if (remote == 0)  
			outFile = sprintf ('%s/time_1st_byte_slice.eps', figFolder); 
		else
			outFile = sprintf ('%s/time_1st_byte_slice_remote.eps', figFolder); 
		end
	end
	if (opt == 3) 
		outFile = sprintf ('%s/time_1st_byte_latency.eps', figFolder); 
	end
	if (opt == 4) 
		outFile = sprintf ('%s/time_1st_byte_proxy.eps', figFolder); 
	end
	if (opt == 5) 
		if (remote == 0)  
			outFile = sprintf ('%s/download_time_fSize_%d.eps', figFolder, rate); 
		else
			outFile = sprintf ('%s/download_time_fSize_remote.eps', figFolder); 
		end	
	end
	if (opt == 6) 
		if (remote == 0)  
			outFile = sprintf ('%s/download_time_browser-like.eps', figFolder); 
		else
			outFile = sprintf ('%s/download_time_browser-like_remote.eps', figFolder); 
		end
	end
	if (opt == 7) 
		if (parallel == 0)  
			outFile = sprintf ('%s/connection_per_second.eps', figFolder); 
		else
			outFile = sprintf ('%s/connection_per_second_%s_%s.eps', figFolder, currMachineLabel, role); 
		end
	end

	% Saving file 
	%saveas (h, outFile, 'psc2');
	outFile
	saveas (fig_handler(jj), outFile, 'psc2');
end

% Addition for comparison file 
if (parallel == 1)  
	figure(comparison); 
	xlabel('No. slices (#)');
	ylabel('Connection per second (cps)');
	legend(leg_comparison, 'Location', 'NorthWest');
	grid on 
	set(0,'defaultaxesfontsize',18);
	t = sprintf('SPP comparison ; Latency=%dms ; N_{prxy}=%d', rtt, N); 
	title(t);
	outFile = sprintf ('%s/connection_per_second_comparison.eps', figFolder) 
	saveas (comparison, outFile, 'psc2');
end
